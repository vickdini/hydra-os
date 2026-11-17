# Group F - Image & live USB (branch i-live)
Current step: running the regression suite on the final kernel
Works so far:
- Clean install image, built by the script from a throwaway copy of the main pool: 5.3 GiB pool (3.3 GiB of data), 951 MiB compressed. Checked by booting it: no hydra/vick accounts, empty /home, no passwords, machine-id, SSH keys, logs, apt lists, network connections, histories, Wine prefixes or browser profiles; no files owned by old user numbers; installer tools present
- USB stick image hydra-live.img (6.25 GiB, fits an 8 GB stick) built and booted in a VM with no CD: starts the live session, logs in by itself as "live", desktop with "Install Hydra" icon and a "You are trying Hydra" window (screenshots scratch/f/s4-1.png, s4-3.png)
- The stick carries the install image in /opt/hydra-install (SHA-256 checked)
- The main pool has ONE damaged object: an orphaned runtime folder of the login screen from 2026-11-09 (nothing personal); the image leaves it out
Next: suite result, final report
