# Group F - Image & live USB (branch i-live)
Current step: running the cleaning step in a throwaway copy of the main pool (VM)
Works so far:
- Pool packer tool (tools/build-image/hydra-pool-pack.c): copies only the live data of a pool into a new compact pool image, checks every block. Run on a copy of the main pool: it found ONE damaged block in the main pool: a runtime folder of the login screen (owner sddm, uid 101, probably /run/user/101; nothing personal). The build now repairs/removes it in the throwaway copy first
- Live session code written (kernel builds): \hydra\live flag on the boot volume -> user "live" logged in by itself, "Install Hydra" on the desktop and in the Start menu, "You are trying Hydra" notice. Not tested yet
- Interface for the installer (Group G) written in LAYOUT.md: /opt/hydra-install/pool.img.zst + esp/
Next: pack + compress the clean image, check it contains nothing personal
