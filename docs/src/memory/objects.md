# Memory objects (`src/lx/mem.rs`, `MemObject` in `src/memory/vm.rs`)

Wave 6, Group 23 ("M" in `docs/linux-services-design.md` 9.1; Group 15's design in
`docs/display-input-design.md`). Services need memory they share with programs and with each
other: DRM dumb buffers and the ALSA ring (display and sound, wave 8), `tmpfs` data and the
mount table (the file service, wave 7), pipe buffers (lx-ipc, wave 9), bulk data between two
services (a direct call's large output). A **memory object** is such a set of pages.

## What a service can do

Native system call **64 `SYS_LX_MEM(op, a, b, c, d)`**, wrapped by `hydra-rt/src/mem.rs`
(`MemObj`). Only registered services may call it.

| Op | Arguments | What |
|---|---|---|
| 1 `LX_MEM_ANON` | size, flags, key | A new zeroed object; pages are allocated on first touch (at most 1 GiB). Flag `LX_MEM_KEPT`: a **kept** object (below); the result has bit 32 set if it already existed |
| 2 `LX_MEM_DMA` | size, `*dev_addr` | Physically contiguous, pinned, zeroed memory (at most 16 MiB) in the caller's IOMMU domain, as `SYS_DMA_ALLOC`; its device address is stored at `dev_addr` |
| 3 `LX_MEM_MAP` | handle, offset, len, prot | Maps part of the object into the caller (shared); returns the address. `/proc/<pid>/maps` names it `[hydra-mem]` |
| 4 `LX_MEM_UNMAP` | addr, len | Unmaps a range of the caller |
| 5 `LX_MEM_CLOSE` | handle | Drops the handle (mappings stay) |
| 6 `LX_MEM_SHARE` | handle, peer endpoint | The design's `LX_SVC_SHARE`: puts the same object into another service's table and returns the peer's handle number (the caller tells the peer by its own protocol) |
| 7 `LX_MEM_INFO` | handle | Pages, bit 48 kept, bit 49 DMA |
| 8 `LX_MEM_UNKEEP` | key | The service forgets one of its kept objects |

**Handles** are small numbers (1..4095) in a table per service *endpoint*: a process's
`task::current_service()`. Linux service ids co-located in one process share its endpoint's
table; native back ends (zfs-server, hda-driver) have tables too, so a back end and a Linux
service can share an object.

## `mmap` of a service's descriptor

A program calls `mmap` on a descriptor a service owns (a `ServerObject`). The kernel's
`mmap` (`compat/linux/mm.rs`, the `Device` arm of `fd_object`) calls
`lx::mem::server_mmap`, which forwards the `mmap` (nr 9, the program's six arguments,
`LxCall::obj` = the slot) to the object's owner with `lx::call_obj`, so the owner routing of
the services design applies unchanged. The owner answers

```text
lx_mmap_answer(handle, object page, read_only) = handle | read_only << 15 | page << 16   (>= 1)
```

or `-errno`. The kernel looks the handle up in the owner's table and maps the object:
`MAP_SHARED` maps its pages, `MAP_PRIVATE` copies them on write, and a read-only answer
refuses `PROT_WRITE` with `EACCES` (and a later `mprotect`). A service (or object kind) with
no memory answers `ENODEV` (linux-server does for every kind but its test object; an old
server's `ENOSYS` becomes `ENODEV` too).

Rule: the handle named in an answer must still be open when the kernel reads the answer.
Close a descriptor's memory on its `LX_NOTE_CLOSE`: a close never overtakes a call on the
same descriptor (the kernel holds the descriptor for the length of the call).

## Lifetimes

- A handle and every mapping (a program's, a service's) hold the object (`Arc<MemObject>`).
  Its pages are freed when the last of them goes.
- **Objects outlive their service.** When a service goes away
  (`ipc::service::unregister` calls `lx::mem::service_gone(endpoint)`), its handle table is
  dropped; programs' mappings keep their pages. The boot log says how many objects were
  still mapped: `[lx-mem] service 0x29 went away: 1 handles dropped (1 objects still mapped or shared, 0 kept)`.
- **Kept objects** belong to the service registry, keyed by `(service id, key)`. A restarted
  instance asks for the same key and gets the old pages (`LX_MEM_EXISTED`). Key 0 is restart
  support's kept-state object (Group 21: `kept_get_or_create(svc, 0, size)`);
  `drop_kept(svc)` forgets them all (the restart ladder's reset). A Transparent service whose
  objects must keep their memory across a restart uses kept objects for it: plain handles
  go with the old instance.

## Kernel API (`crate::lx::mem`)

`MemObject` (a `MappedObject`: `anon(pages)`, `frames(base, pages, owned, on_drop)`,
`pages()`, `phys_base()`, `resident()`), `anon(size)`, `frames(base, pages)` (kernel-made DMA
objects: the sound rings of wave 8), `give(endpoint, obj) -> handle`, `get(endpoint, handle)`,
`map_current(obj, offset, len, prot, fixed)`, `kept_get_or_create`, `drop_kept`, `kept_list`,
`service_gone`, `server_mmap`, `summary`.

## Cost

Nothing on the paths that existed: the anonymous-fault and `mmap` paths are unchanged; only
`mmap` of a server object (which failed with `ENODEV` before) makes a forwarded call. A page
of an anonymous memory object is found or allocated under the object's lock, as a memfd's.

## Tests

- `tests/linux/srvmap_test.c` (`esp/bin/srvmap.elf`, in the suite after `persona`):
  linux-server's test object has 64 KiB of memory (ioctls `0x4D50` peek, `0x4D51` poke,
  `0x4D52` drop, `0x4D53` share, `0x4D54` info; flags bit 32 kept, bit 33 DMA). Checks:
  writes from both sides, a second mapping at an offset, a private copy, ranges past the
  end, read-only mappings, `fork`, `LX_MEM_SHARE`, `ENODEV` for an eventfd, the mapping
  outliving `close` and the server's handle, DMA memory, 300 objects without a leak.
- Kept across a kill: `srvmap keep-write`, `service restart linux_server` in hydra-shell,
  `srvmap keep-check` (the stamp survives); `srvmap hold N` keeps a mapping in use during
  the kill.
- Host tests (`tests/host/tests/vm.rs`, `mem_object_*`): pages on first touch, sharing
  across address spaces and `fork`, private copy-on-write, owned and borrowed frames.
