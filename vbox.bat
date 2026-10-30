@echo off
setlocal
set "VBOX=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
set "QEMU_IMG=C:\Program Files\qemu\qemu-img.exe"
set "DIST=%~dp0dist\x86_64"
set "VM=Hydra"

echo [*] Building Hydra OS (release)...
cargo build --release --target x86_64-unknown-uefi
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

echo [*] Packaging UEFI bootable ISO via WSL...
wsl bash -c "cd /mnt/d/os && make build"
if errorlevel 1 (
    echo [!] ISO packaging failed.
    exit /b 1
)

rem Storage can only be reconfigured while the VM is powered off
"%VBOX%" showvminfo "%VM%" --machinereadable | findstr /C:"VMState=\"running\"" >nul
if not errorlevel 1 (
    echo [!] VM "%VM%" is running. Shut it down first, then run vbox.bat again.
    exit /b 1
)

rem ZFS pool disk (16 GiB, grows on demand). The first time, convert the QEMU pool so the
rem VM starts with the same files (including an installed Ubuntu); otherwise create an empty one.
if not exist "%DIST%\hydrapool.vdi" (
    if exist "%DIST%\hydrapool.qcow2" (
        echo [*] Converting QEMU pool hydrapool.qcow2 to hydrapool.vdi...
        "%QEMU_IMG%" convert -O vdi "%DIST%\hydrapool.qcow2" "%DIST%\hydrapool.vdi"
    ) else (
        echo [*] Creating 16 GiB ZFS pool disk hydrapool.vdi...
        "%VBOX%" createmedium disk --filename "%DIST%\hydrapool.vdi" --size 16384 --format VDI --variant Standard
    )
    if errorlevel 1 (
        echo [!] Could not create the pool disk.
        exit /b 1
    )
)

rem Optional installation media (Ubuntu rootfs archive), built by `make rootfs-media`
if exist "%DIST%\rootfs-media.img" if not exist "%DIST%\rootfs-media.vdi" (
    echo [*] Converting rootfs-media.img to rootfs-media.vdi...
    "%QEMU_IMG%" convert -O vdi "%DIST%\rootfs-media.img" "%DIST%\rootfs-media.vdi"
)

echo [*] Configuring VM: 4 GiB RAM, EFI, Intel 82540EM NIC on NAT, serial log...
"%VBOX%" modifyvm "%VM%" --memory 4096 --firmware efi --nic1 nat --nictype1 82540EM ^
    --uart1 0x3F8 4 --uartmode1 file "%~dp0scratch\vbox_serial.log"

echo [*] Attaching ZFS pool disk to Primary Master [IDE-0-0]...
"%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 0 --type hdd --medium "%DIST%\hydrapool.vdi"
if errorlevel 1 (
    echo [!] Could not attach hydrapool.vdi.
    exit /b 1
)

if exist "%DIST%\rootfs-media.vdi" (
    echo [*] Attaching rootfs installation media to Primary Slave [IDE-0-1]...
    "%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 1 --type hdd --medium "%DIST%\rootfs-media.vdi"
) else (
    "%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 1 --medium none >nul 2>&1
)

echo [*] Attaching updated kernel.iso to Secondary Master [IDE-1-0]...
"%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 1 --device 0 --type dvddrive --medium "%DIST%\kernel.iso"
if errorlevel 1 (
    echo [!] Could not attach kernel.iso.
    exit /b 1
)

echo [*] Launching Hydra in VirtualBox (serial output: scratch\vbox_serial.log)...
"%VBOX%" startvm "%VM%" --type gui
