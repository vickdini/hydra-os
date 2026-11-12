@echo off
setlocal

rem One VM at a time: two QEMUs on the same pool image corrupt it (QEMU on Windows does
rem not stop a second one), and the build below rewrites the boot image a VM may be using
powershell -NoProfile -Command "if (Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue) { exit 1 }"
if errorlevel 1 (
    echo [!] A QEMU VM is already running ^(another qemu.bat or a test run^). Close it first:
    echo     two VMs on hydrapool.qcow2 at once corrupt the pool.
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

if not exist "%~dp0dist\x86_64\hydrapool.qcow2" (
    echo [*] Creating 16 GiB ZFS pool disk image ^(qcow2, grows on demand^)...
    "C:\Program Files\qemu\qemu-img.exe" create -f qcow2 "%~dp0dist\x86_64\hydrapool.qcow2" 16G >nul
)

rem Hardware virtualization (WHPX) unless HYDRA_ACCEL=tcg. WHPX cannot emulate OVMF's
rem flash chip, so the firmware is loaded as a ROM: variable store + code, as in OVMF.fd
set "QEMU_SHARE=C:\Program Files\qemu\share"
if /i "%HYDRA_ACCEL%"=="tcg" (
    set FIRMWARE=-drive "if=pflash,format=raw,readonly=on,file=%QEMU_SHARE%\edk2-x86_64-code.fd"
) else (
    if not exist "%~dp0target\OVMF-whpx.fd" copy /b "%QEMU_SHARE%\edk2-i386-vars.fd" + "%QEMU_SHARE%\edk2-x86_64-code.fd" "%~dp0target\OVMF-whpx.fd" >nul
    set FIRMWARE=-accel whpx,kernel-irqchip=off -bios "%~dp0target\OVMF-whpx.fd"
)

rem CPUs for the VM: 4 unless HYDRA_SMP says otherwise (QEMU's default is 1)
if not defined HYDRA_SMP set HYDRA_SMP=4

rem The boot ISO is on virtio-scsi: the firmware reads the kernel and the boot files by DMA
rem (several times faster than the IDE CD-ROM); Hydra needs it only until it takes over
echo [*] Launching Hydra in QEMU (Display ON, Storage Disk attached, Intel E1000 NIC)...
start "" "C:\Program Files\qemu\qemu-system-x86_64.exe" %FIRMWARE% -drive file="%~dp0dist\x86_64\hydrapool.qcow2",format=qcow2,index=0,media=disk -netdev user,id=net0 -device e1000,netdev=net0 -device virtio-scsi-pci,id=scsi0 -drive file="%~dp0dist\x86_64\kernel.iso",if=none,id=bootcd,media=cdrom,format=raw -device scsi-cd,drive=bootcd,bootindex=0 -m 4G -smp %HYDRA_SMP% -vga std -display gtk %*