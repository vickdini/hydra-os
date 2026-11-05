with open('src/compat/linux/vfs.rs', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Line 796
old_stat = """        Some(FileDescriptor::MemFd(m)) => {
            // PipeWire checks st_size (and st_dev/st_ino) before mapping a shared block
            let mut st = anon_stat(Arc::as_ptr(&m) as *const u8, S_IFREG | 0o777);
            st.st_size = m.lock().size() as i64;
            st.st_blocks = (st.st_size + 511) / 512;
            Some(Ok(st))
        }"""

new_stat = """        Some(FileDescriptor::MemFd { memfd: m, flags }) => {
            // PipeWire and Chromium check st_size and permissions before mapping
            let mode = if flags & 3 == 0 { S_IFREG | 0o444 } else { S_IFREG | 0o666 };
            let mut st = anon_stat(Arc::as_ptr(&m) as *const u8, mode);
            st.st_size = m.lock().size() as i64;
            st.st_blocks = (st.st_size + 511) / 512;
            Some(Ok(st))
        }"""
assert old_stat in text, 'old_stat not found'
text = text.replace(old_stat, new_stat)

# 2. Line 896
old_reopen = """                            FileDescriptor::MemFd(m) => {
                                return install(FileDescriptor::MemFd(m), flags);
                            }"""
new_reopen = """                            FileDescriptor::MemFd { memfd: m, .. } => {
                                return install(FileDescriptor::MemFd { memfd: m, flags }, flags);
                            }"""
assert old_reopen in text, 'old_reopen not found'
text = text.replace(old_reopen, new_reopen)

# 3. Line 919-921
old_snap = """        let snapshot = super::memfd::MemFd::new(&abs);
        snapshot.lock().write_at(0, &text);
        return install(FileDescriptor::MemFd(snapshot), flags);"""
new_snap = """        let snapshot = super::memfd::MemFd::new(&abs);
        snapshot.lock().write_at(0, &text);
        return install(FileDescriptor::MemFd { memfd: snapshot, flags: 0 }, flags);"""
assert old_snap in text, 'old_snap not found'
text = text.replace(old_snap, new_snap)

# 4. Line 1306
old_link = 'FileDescriptor::MemFd(_) => String::from("/memfd: (deleted)"),'
new_link = 'FileDescriptor::MemFd { .. } => String::from("/memfd: (deleted)"),'
assert old_link in text, 'old_link not found'
text = text.replace(old_link, new_link)

# 5. Line 2311-2314
old_falloc = """        285 if matches!(crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned()), Some(FileDescriptor::MemFd(_))) => {
            // fallocate on a memfd: pages are allocated when touched; only the size grows
            let m = match crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned()) {
                Some(FileDescriptor::MemFd(m)) => m,
                _ => return Some(EBADF),
            };"""
new_falloc = """        285 if matches!(crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned()), Some(FileDescriptor::MemFd { .. })) => {
            // fallocate on a memfd: pages are allocated when touched; only the size grows
            let m = match crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned()) {
                Some(FileDescriptor::MemFd { memfd, .. }) => memfd,
                _ => return Some(EBADF),
            };"""
assert old_falloc in text, 'old_falloc not found'
text = text.replace(old_falloc, new_falloc)

# 6. fcntl
old_fcntl = """        F_GETFL => match fd_vnode(fd as i32) {
            Some(f) => f.lock().flags as i64,
            None => return None,
        },
        F_SETFL => match fd_vnode(fd as i32) {
            Some(f) => {
                let mut f = f.lock();
                f.flags = (f.flags & !(O_APPEND | O_NONBLOCK)) | (arg as u32 & (O_APPEND | O_NONBLOCK));
                0
            }
            None => return None,
        },
        F_GETLK => {
            // No other process holds locks: report the region as unlocked (l_type = F_UNLCK)
            match copy_out(arg, &2i16.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        F_SETLK | F_SETLKW => 0,
        F_ADD_SEALS | F_GET_SEALS => 0,"""

new_fcntl = """        F_GETFL => {
            let fl = crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
                Some(FileDescriptor::MemFd { flags, .. }) => Some(*flags as i64),
                Some(FileDescriptor::File { readable, writable, append, .. }) => {
                    let mode = if *readable && *writable { 2 } else if *writable { 1 } else { 0 };
                    Some(mode | if *append { 0o2000 } else { 0 })
                }
                _ => None,
            });
            if let Some(flags) = fl {
                flags
            } else {
                match fd_vnode(fd as i32) {
                    Some(f) => f.lock().flags as i64,
                    None => return None,
                }
            }
        }
        F_SETFL => {
            let handled = crate::task::with_current_fds_mut(|fds| match fds.get_mut(fd) {
                Some(FileDescriptor::MemFd { flags, .. }) => {
                    *flags = (*flags & !(O_APPEND | O_NONBLOCK)) | (arg as u32 & (O_APPEND | O_NONBLOCK));
                    Some(0)
                }
                Some(FileDescriptor::File { append, .. }) => {
                    *append = arg as u32 & O_APPEND != 0;
                    Some(0)
                }
                _ => None,
            });
            if let Some(res) = handled {
                res
            } else {
                match fd_vnode(fd as i32) {
                    Some(f) => {
                        let mut f = f.lock();
                        f.flags = (f.flags & !(O_APPEND | O_NONBLOCK)) | (arg as u32 & (O_APPEND | O_NONBLOCK));
                        0
                    }
                    None => return None,
                }
            }
        }
        F_GETLK => {
            // No other process holds locks: report the region as unlocked (l_type = F_UNLCK)
            match copy_out(arg, &2i16.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        F_SETLK | F_SETLKW => 0,
        F_GET_SEALS => {
            let m = crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
                Some(FileDescriptor::MemFd { memfd, .. }) => Some(memfd.clone()),
                _ => None,
            });
            match m {
                Some(memfd) => memfd.lock().seals as i64,
                None => -EINVAL,
            }
        }
        F_ADD_SEALS => {
            let m = crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
                Some(FileDescriptor::MemFd { memfd, .. }) => Some(memfd.clone()),
                _ => None,
            });
            match m {
                Some(memfd) => {
                    let mut mem = memfd.lock();
                    const F_SEAL_SEAL: u32 = 0x0001;
                    if mem.seals & F_SEAL_SEAL != 0 && (arg as u32 & !mem.seals) != 0 {
                        -EPERM
                    } else {
                        mem.seals |= arg as u32;
                        0
                    }
                }
                None => -EINVAL,
            }
        }"""
assert old_fcntl in text, 'old_fcntl not found'
text = text.replace(old_fcntl, new_fcntl)

with open('src/compat/linux/vfs.rs', 'w', encoding='utf-8') as f:
    f.write(text)
print('Updated vfs.rs successfully')

