@echo off
setlocal enabledelayedexpansion

set "VBOX_DIR=C:\Program Files\Oracle\VirtualBox"
set "VBOX=%VBOX_DIR%\VBoxManage.exe"
set "VBOX_GUI=%VBOX_DIR%\VirtualBoxVM.exe"
set "QEMU_IMG=C:\Program Files\qemu\qemu-img.exe"
set "DIST=%~dp0dist\x86_64"
set "VM=Hydra"

set "DO_SYNC=0"
set "DO_BUILD=1"

:parse_args
if "%~1"=="" goto after_args
if /i "%~1"=="--sync" set "DO_SYNC=1"
if /i "%~1"=="-s" set "DO_SYNC=1"
if /i "%~1"=="--refresh" set "DO_SYNC=1"
if /i "%~1"=="--no-build" set "DO_BUILD=0"
if /i "%~1"=="-n" set "DO_BUILD=0"
shift
goto parse_args
:after_args

if not exist "%VBOX%" (
    echo [!] VirtualBox not found at: "%VBOX%"
    exit /b 1
)

if "%DO_BUILD%"=="0" goto skip_build
echo [*] Building Hydra OS [release]...
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
:skip_build

rem Ensure VM exists; create it if not present
"%VBOX%" showvminfo "%VM%" >nul 2>&1
if not errorlevel 1 goto vm_exists
echo [*] VM "%VM%" does not exist in VirtualBox. Creating and registering...
"%VBOX%" createvm --name "%VM%" --ostype "Other_64" --register
if errorlevel 1 (
    echo [!] Failed to create VM "%VM%".
    exit /b 1
)
"%VBOX%" storagectl "%VM%" --name "IDE" --add ide --controller PIIX4
:vm_exists

rem Check if VM is running
"%VBOX%" showvminfo "%VM%" --machinereadable | findstr /C:"VMState=\"running\"" >nul
if errorlevel 1 goto vm_not_running
echo [!] VM "%VM%" is currently running. Please close it first.
exit /b 1
:vm_not_running

rem Determine if ZFS pool synchronization is needed
if not exist "%DIST%\hydrapool.qcow2" goto check_vdi_exists

if not exist "%DIST%\hydrapool.vdi" (
    set "DO_SYNC=1"
    goto do_sync_pool
)

if "%DO_SYNC%"=="1" goto do_sync_pool

for /f %%A in ('powershell -NoProfile -Command "$q = (Get-Item '%DIST%\hydrapool.qcow2').LastWriteTime; $v = (Get-Item '%DIST%\hydrapool.vdi').LastWriteTime; if ($q -gt $v) { 'YES' } else { 'NO' }"') do (
    if "%%A"=="YES" (
        echo [*] Detected hydrapool.qcow2 is newer than hydrapool.vdi.
        set "DO_SYNC=1"
    )
)

if "%DO_SYNC%"=="1" goto do_sync_pool
goto configure_vm

:do_sync_pool
echo [*] Synchronizing latest ZFS pool from hydrapool.qcow2 to hydrapool.vdi...

rem Detach old medium if attached
"%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 0 --medium none >nul 2>&1

rem Unregister old medium from VirtualBox registry if present
if exist "%DIST%\hydrapool.vdi" (
    "%VBOX%" closemedium disk "%DIST%\hydrapool.vdi" >nul 2>&1
    del /f /q "%DIST%\hydrapool.vdi" >nul 2>&1
)

"%QEMU_IMG%" convert -O vdi "%DIST%\hydrapool.qcow2" "%DIST%\hydrapool.vdi"
if errorlevel 1 (
    echo [!] Failed to convert hydrapool.qcow2 to VDI.
    exit /b 1
)
echo [+] hydrapool.vdi successfully synchronized with latest pool data.
goto configure_vm

:check_vdi_exists
if exist "%DIST%\hydrapool.vdi" goto configure_vm
echo [*] Creating 16 GiB ZFS pool disk hydrapool.vdi...
"%VBOX%" createmedium disk --filename "%DIST%\hydrapool.vdi" --size 16384 --format VDI --variant Standard
if errorlevel 1 (
    echo [!] Could not create the pool disk.
    exit /b 1
)

:configure_vm
echo [*] Configuring VM: 4 GiB RAM, 2 CPUs, EFI firmware, 128MB VRAM, Intel 82540EM NIC on NAT...
"%VBOX%" modifyvm "%VM%" ^
    --memory 4096 ^
    --cpus 2 ^
    --firmware efi ^
    --vram 128 ^
    --graphicscontroller vboxvga ^
    --defaultfrontend gui ^
    --boot1 dvd --boot2 disk --boot3 none --boot4 none ^
    --nic1 nat --nictype1 82540EM ^
    --natdnsproxy1 on --natdnshostresolver1 on ^
    --mouse ps2 --keyboard ps2 ^
    --uart1 0x3F8 4 --uartmode1 file "%~dp0scratch\vbox_serial.log"

"%VBOX%" setextradata "%VM%" "VBoxInternal/Devices/e1000/0/Config/LinkUpDelay" "0" >nul 2>&1

echo [*] Attaching ZFS pool disk [IDE-0-0: Primary Master]...
"%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 0 --type hdd --medium "%DIST%\hydrapool.vdi" >nul 2>&1
if errorlevel 1 (
    "%VBOX%" internalcommands sethduuid "%DIST%\hydrapool.vdi" c74cb2ef-2258-4a8a-9319-75f0cd4ab159 >nul 2>&1
    "%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 0 --type hdd --medium "%DIST%\hydrapool.vdi"
    if errorlevel 1 (
        echo [!] Could not attach hydrapool.vdi.
        exit /b 1
    )
)

if exist "%DIST%\rootfs-media.vdi" (
    echo [*] Attaching rootfs installation media [IDE-0-1: Primary Slave]...
    "%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 1 --type hdd --medium "%DIST%\rootfs-media.vdi"
) else (
    "%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 0 --device 1 --medium none >nul 2>&1
)

echo [*] Attaching UEFI boot ISO [IDE-1-0: Secondary Master]...
"%VBOX%" storageattach "%VM%" --storagectl "IDE" --port 1 --device 0 --type dvddrive --medium "%DIST%\kernel.iso"
if errorlevel 1 (
    echo [!] Could not attach kernel.iso.
    exit /b 1
)

echo [*] Launching Hydra in VirtualBox [serial log: scratch\vbox_serial.log]...
if exist "%VBOX_GUI%" (
    start "" "%VBOX_GUI%" --startvm "%VM%"
) else (
    "%VBOX%" startvm "%VM%" --type gui
)
