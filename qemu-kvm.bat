@echo off
setlocal

rem Hydra in a QEMU window with KVM inside WSL2 (tools/hydra-kvm.sh): faster than qemu.bat's WHPX
rem for disk work and starting programs. It uses the pool copy inside WSL, not dist\x86_64\hydrapool.qcow2.

rem The build below rewrites the boot image a running VM may be using
powershell -NoProfile -Command "if (Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue) { exit 1 }"
if errorlevel 1 (
    echo [!] A Windows QEMU VM is running ^(qemu.bat or a test run^). Close it first.
    exit /b 1
)
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

rem Root in WSL: the chroot holding QEMU, its mounts and /dev/kvm. Line endings stripped, in case
rem the script was checked out with Windows ones
wsl -d Ubuntu-20.04 -u root -e bash -c "tr -d '\r' < /mnt/d/os/tools/hydra-kvm.sh | bash -s -- %*"
