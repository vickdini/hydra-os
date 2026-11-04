with open('src/compat/linux/vfs.rs', 'rb') as f:
    data = f.read()

start = data.find(b'    if fd == 0 {')
end = data.find(b'    match desc {', start)

if start != -1 and end != -1:
    data = data[:start] + data[end:]
    with open('src/compat/linux/vfs.rs', 'wb') as f:
        f.write(data)
    print("Cleaned vfs.rs successfully")
else:
    print("Not found", start, end)

