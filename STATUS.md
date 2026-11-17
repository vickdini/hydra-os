# Group F - Image & live USB (branch i-live)
Current step: the USB stick image is built (6.25 GiB) and boots by itself into the live desktop; now finding out why the "You are trying Hydra" notice does not show, then the regression suite
Works so far:
- Clean install image, built twice by the script from a throwaway copy of the main pool: 5.3 GiB pool (3.3 GiB of data), 951 MiB compressed. Checked by booting it: no hydra/vick accounts, empty /home, no passwords, machine-id, SSH keys, logs, apt lists, network connections, histories, Wine prefixes or browser profiles; no files owned by the old user numbers; installer tools present
- Live system (the clean image plus the install files in /opt/hydra-install, SHA-256 checked): logs in by itself as "live", "Install Hydra" icon on the desktop (screenshots scratch/f/live1-*.png, live2-*.png)
- Group E's disk work merged (3f172e9)
- The main pool has ONE damaged object: an orphaned runtime folder of the login screen from 2026-11-09 (nothing personal); the image leaves it out
Not verified: the "You are trying Hydra" notice (fix 67919f7 not yet booted), the stick image hydra-live.img (script written, not run), the regression suite
Next: when WSL works: build-image.sh liveiso stick, boot scratch/f/stickdesk.sh, run the suite
