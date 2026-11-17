# Group F - Image & live USB (branch i-live)
Current step: building the USB stick image (hydra-live.img) and booting it in a VM; the WSL machine is slow right now
Works so far:
- Clean install image (built twice by the script from a throwaway copy of the main pool): 5.3 GiB pool with 3.3 GiB of data, 951 MiB compressed. Verified by booting it: no accounts hydra/vick, empty /home, no passwords, machine-id, SSH keys, logs, apt lists, network connections, histories, Wine prefixes, browser profiles; no files owned by the old user numbers; installer tools present
- The live system (clean image + install files in /opt/hydra-install, checked by SHA-256) logs in by itself as "live" into the desktop with the "Install Hydra" icon (screenshots scratch/f/live1-*.png, live2-*.png)
- Group E's disk work merged into my branch (commit 3f172e9)
- The main pool has ONE damaged object: an orphaned runtime folder of the login screen from 2026-11-09 (nothing personal); the image leaves it out
Not working yet: the "You are trying Hydra" notification did not appear (wrong argument types in the call; fixed, retesting)
Next: boot the stick image directly (no ISO), screenshot the notification
