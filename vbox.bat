@echo off
setlocal
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

if not exist "%~dp0dist\x86_64\storage.vdi" (
    echo [*] Creating persistent ATA storage virtual disk [64MB]...
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "%~dp0dist\x86_64\storage.vdi" --size 64 --format VDI
)

echo [*] Attaching persistent storage disk to Primary Master [IDE-0-0]...
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "Hydra" --storagectl "IDE" --port 0 --device 0 --type hdd --medium "%~dp0dist\x86_64\storage.vdi"

echo [*] Attaching updated kernel.iso to Secondary Master [IDE-1-0]...
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "Hydra" --storagectl "IDE" --port 1 --device 0 --type dvddrive --medium "%~dp0dist\x86_64\kernel.iso"

echo [*] Ensuring Intel 82540EM Gigabit NIC is configured on NAT...
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "Hydra" --nic1 nat --nictype1 82540EM

echo [*] Launching Hydra in VirtualBox...
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "Hydra" --type gui
