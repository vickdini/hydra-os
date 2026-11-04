with open('src/compat/linux/vfs.rs', 'rb') as f:
    content = f.read()

target = b'let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe()));'
replacement = b'let exe = crate::task::SCHEDULER.lock().current_task_mut(|t| alloc::string::String::from(t.exe.as_deref().unwrap_or(t.name)));'

if target in content:
    content = content.replace(target, replacement, 1)
    with open('src/compat/linux/vfs.rs', 'wb') as f:
        f.write(content)
    print("Fixed t.exe call")
else:
    print("Target not found")
