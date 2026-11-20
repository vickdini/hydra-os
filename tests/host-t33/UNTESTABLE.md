# Group 33: code the host tests cannot run

Everything listed here needs the UEFI firmware, runs forever, or is evaluated by the
compiler, not at run time. All other code of Group 33's files is compiled into
`tests/host-t33` and tested (see the per-file numbers in the final report).

| File | Function / lines | Why |
|---|---|---|
| `src/fs/bootfs.rs` | `open_root_volume` (after the hardware-mode check), `fw_read`, `read_media_file`, `read_boot_file`, `file_exists` (after their hardware-mode checks) | UEFI Boot Services (`SimpleFileSystem`, `allocate_pages`, `RegularFile`): a host process has no firmware. The hardware-mode answers and `path_to_cstr16` are tested. |
| `src/fs/firstboot.rs` | `read_from_boot_volume` (lines 42-81) | Opens and deletes `\hydra\setup.conf` through the UEFI file protocol. Its decisions were split out (`usable_size`, `stage`) and are tested, as is `import_into_pool`. |
| `src/fs/client.rs` | `ZfsClient::read_boot_files` past the hardware-mode check (lines ~1067-1147) | Reads the boot volume through UEFI. `import_boot_files`, which takes what it read, is tested. |
| `src/fs/client.rs` | `txgd_main` (lines 1342-1346) | The `txgd` kernel task's endless loop (sleep, commit). `start_txg_sync` and `sync_if_dirty`, its body, are tested. |
| `src/compress/gzip.rs` | `make_crc32_table` (lines 51-69) | A `const fn` evaluated at compile time (`CRC32_TABLE`); the table is checked through `crc32`. |
| `src/personality/freebsd.rs` | `entries` (lines 59-80) | A `const fn` evaluated at compile time (`TABLE`); every entry is checked through calls. |
| `src/fs/mod.rs`, `src/pkg/mod.rs` | whole file | Module declarations and re-exports only (no executable lines); compiled into the crate as the module roots of `crate::fs` and `crate::pkg`. |
| `src/compat/mod.rs` | whole file | One line, `pub mod linux;`: compiling it would compile the whole Linux layer's `mod.rs` hub (other groups' files). Nothing to test. |

Other lines the coverage tool shows as missed are error branches that need a fault the
host cannot make (a user pointer that is not mapped: with no address space every host
address is "present", so `copy_out` fails only for address 0).
