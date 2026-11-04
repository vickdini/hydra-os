with open('src/compat/linux/vfs.rs', 'rb') as f:
    text = f.read()

text = text.replace(b'return Err(ENOENT);', b'return Err(-ENOENT);')
text = text.replace(b'.ok_or(EBADF)?;', b'.ok_or(-EBADF)?;')

trace_code = b'''    if dirfd == 0 || (path.is_empty() && (flags & AT_EMPTY_PATH != 0)) {
        let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe.as_deref().unwrap_or(t.name)));
        if let Some(ref e) = exe {
            if e.contains("sddm-helper") {
                crate::kprintln!("[sddm-helper] stat_at dirfd={} flags=0x{:x}", dirfd, flags);
            }
        }
    }
'''

target = b'    let path = user_cstr(path_ptr)?;\r\n'
if target in text:
    text = text.replace(target, target + trace_code)
else:
    target = b'    let path = user_cstr(path_ptr)?;\n'
    text = text.replace(target, target + trace_code)

trace_fstat = b'''    if fd == 0 {
        let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe.as_deref().unwrap_or(t.name)));
        if let Some(ref e) = exe {
            if e.contains("sddm-helper") {
                let dname = match &desc {
                    None => "None",
                    Some(FileDescriptor::ConsoleIn) => "ConsoleIn",
                    Some(FileDescriptor::Socket(_)) => "Socket",
                    Some(FileDescriptor::Unix(_)) => "Unix",
                    _ => "Other",
                };
                crate::kprintln!("[sddm-helper] fstat_fd(0) desc={}", dname);
            }
        }
    }
'''

target2 = b'    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());\r\n'
if target2 in text:
    text = text.replace(target2, target2 + trace_fstat)
else:
    target2 = b'    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());\n'
    text = text.replace(target2, target2 + trace_fstat)

with open('src/compat/linux/vfs.rs', 'wb') as f:
    f.write(text)
print("Updated vfs.rs")

