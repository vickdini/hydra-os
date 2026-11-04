with open('src/compat/linux/vfs.rs', 'rb') as f:
    content = f.read()

target = b'    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());\r\n    match desc {'
replacement = b'''    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());
    if fd == 0 {
        let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe()));
        if let Some(ref e) = exe {
            if e.contains("sddm-helper") {
                let desc_name = match &desc {
                    None => "None",
                    Some(FileDescriptor::ConsoleIn) => "ConsoleIn",
                    Some(FileDescriptor::Socket(_)) => "Socket",
                    Some(FileDescriptor::Unix(_)) => "Unix",
                    Some(FileDescriptor::Inet(_)) => "Inet",
                    Some(FileDescriptor::PipeRead(_)) => "PipeRead",
                    Some(FileDescriptor::PipeWrite(_)) => "PipeWrite",
                    Some(FileDescriptor::File { path, .. }) => "File",
                    Some(FileDescriptor::Vnode(_)) => "Vnode",
                    Some(FileDescriptor::Device(_)) => "Device",
                    _ => "Other",
                };
                crate::kprintln!("[sddm-helper] fstat(0) desc={}", desc_name);
            }
        }
    }
    match desc {'''

replacement_crlf = replacement.replace(b'\n', b'\r\n')
if target in content:
    content = content.replace(target, replacement_crlf, 1)
    with open('src/compat/linux/vfs.rs', 'wb') as f:
        f.write(content)
    print("Injected sddm-helper debug trace into fstat_fd")
else:
    print("Target not found")

