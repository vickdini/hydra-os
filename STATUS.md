# Group G - Installer app & first boot (branch i-setup)
Current step: decided the installer framework; writing the installer window and its root helper
Works so far:
- Decision: our own installer window in Python + PyQt6 (like Hydra Apps), NOT Calamares. Why: Calamares is in Ubuntu 26.04 (3.3.14) but its disk page needs KPMcore + libparted + udev, which see only "known" Linux filesystems and real block devices; Hydra's pool partition is neither, and the installer must never mount the target. Its install modules (unpackfs, bootloader, users) all work by mounting the new system and changing files inside it, which our design forbids (settings are applied at first boot instead). It would also pull in about 30 extra libraries (Qt Quick/QML, KF6 parts, yaml-cpp, os-prober). Our own window is about the same amount of work as taming Calamares and does exactly the 7 Windows-Setup-like steps.
Next: installer window + helper, tested on a disk image file in the WSL chroot
