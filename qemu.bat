@echo off
setlocal
echo [*] Building Hydra OS (release)...
cargo build --release --target x86_64-unknown-uefi
if errorlevel 1 (
    echo [!] Cargo build failed.
    exit /b 1
)

echo [*] Packaging UEFI bootable ISO via WSL...
wsl bash -c "cd /mnt/d/os && make build"
if errorlevel 1 (
    echo [!] ISO packaging failed.
    exit /b 1
)

echo [*] Updating ESP bootloader...
copy /Y target\x86_64-unknown-uefi\release\hydra.efi esp\EFI\BOOT\BOOTX64.EFI >nul

if not exist "%~dp0dist\x86_64\hydrapool.qcow2" (
    echo [*] Creating 16 GiB ZFS pool disk image ^(qcow2, grows on demand^)...
    "C:\Program Files\qemu\qemu-img.exe" create -f qcow2 "%~dp0dist\x86_64\hydrapool.qcow2" 16G >nul
)

echo [*] Launching Hydra in QEMU (Display ON, Storage Disk attached, Intel E1000 NIC)...
start "" "C:\Program Files\qemu\qemu-system-x86_64.exe" -drive "if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd" -drive file="%~dp0dist\x86_64\hydrapool.qcow2",format=qcow2,index=0,media=disk -netdev user,id=net0 -device e1000,netdev=net0 -cdrom "%~dp0dist\x86_64\kernel.iso" -boot d -m 4G -vga std -display gtk %*