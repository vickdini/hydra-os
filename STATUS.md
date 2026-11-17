# Group G - Installer app & first boot (branch i-setup)
Current step: end-to-end install WORKS; now running the regression suite, then the final report
Works so far:
- Decision: our own installer window in Python + PyQt6 (like Hydra Apps), NOT Calamares (its disk page needs KPMcore/libparted/udev and filesystems it knows; its install steps mount the new system, which our design forbids; ~30 extra libraries).
- END TO END (VM, merged with Group E's disk branch, Group F's clean image): the installer window in KDE erased a blank 32 GB second disk, made the two partitions, wrote and checked the 5.7 GB clean image (about 4 minutes), copied the start-up files and the settings, and added "Hydra" first in the computer's start-up list. Then the VM started from that disk ALONE (no CD): the first start created the account Anna Schmidt (anna, uid 1000, administrator), computer name anna-pc, Europe/Berlin, German keyboard and formats, a new machine id, deleted the settings from the start-up partition; logging in as anna with the password chosen in the installer reached the desktop. Pictures: scratch/g-e2e (installer pages and progress), scratch/g-e2e2 and g-e2e2b (desktop of the new user).
- Error handling checked: damaged image, bad user name, too-small disk, mkfs refusing, folder already there: each gives a plain message and never "installed".
- Not yet: German translations of Plasma are fetched in the background at the first start; this failed in the test (the clean image has no package lists); fixed (apt-get update first) but not re-tested.
Next: regression suite, final report
