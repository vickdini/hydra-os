# Group F - Image & live USB (branch i-live)
Current step: second full run of the image build (cleaning, packing, checking) followed by the live stick's system
Works so far:
- Clean install image built from a throwaway copy of the main pool (first run): 5.3 GiB pool (3.3 GiB of data, 2 GiB free), 951 MiB compressed with zstd. Verified by booting it in a VM: no accounts hydra/vick, empty /home, no passwords, no machine-id, no SSH keys, logs, journal, apt lists, network connections, histories, Wine prefixes or browser profiles; installer tools (zstd, sgdisk, sfdisk, mkfs.vfat, mcopy, efibootmgr) present
- Found and fixed: Wine Mono files were still owned by the old user number 1000 (the second run gives them to root)
- The main pool has ONE damaged object: an orphaned runtime folder of the login screen from 2026-11-09 (nothing personal, no directory names it); the image leaves it out
- Live session code written (kernel builds); interface for the installer (Group G) in LAYOUT.md
Next: put the install image into the live stick's system, take screenshots of the live desktop
