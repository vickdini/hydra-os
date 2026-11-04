with open('src/compat/linux/vfs.rs', 'r', encoding='utf-8') as f:
    content = f.read()

target1 = """    let path = user_cstr(path_ptr)?;
    if dirfd == 0 || (path.is_empty() && (flags & AT_EMPTY_PATH != 0)) {
        let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe.as_deref().unwrap_or(t.name)));
        if let Some(ref e) = exe {
            if e.contains("sddm-helper") {
                crate::kprintln!("[sddm-helper] stat_at dirfd={} flags=0x{:x}", dirfd, flags);
            }
        }
    }
    if path.is_empty() {"""

repl1 = """    let path = user_cstr(path_ptr)?;
    if path.is_empty() {"""

target2 = """    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());
    if fd == 0 {
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
    match desc {"""

repl2 = """    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());
    match desc {"""

assert target1 in content, "target1 not found"
assert target2 in content, "target2 not found"

content = content.replace(target1, repl1).replace(target2, repl2)
with open('src/compat/linux/vfs.rs', 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print("Successfully cleaned vfs.rs debug traces")
