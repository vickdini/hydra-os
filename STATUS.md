# Group F - Image & live USB (branch i-live)
Current step: writing the image tools; the WSL Linux machine has not answered for ~35 minutes (all groups wait for it)
Works so far:
- Pool packer tool (tools/build-image/hydra-pool-pack.c): copies only the live data of a pool into a new compact pool image, checks every block. First run on a copy of the main pool: it found ONE damaged block in the main pool (block 922603), so it refused to pack; finding which file it is when WSL answers again
- Live session code written (kernel builds): \hydra\live flag on the boot volume -> user "live" logged in by itself, "Install Hydra" on the desktop and in the Start menu, "You are trying Hydra" notice. Not tested yet
Next: when WSL answers: find the damaged file, run the cleaning script in a throwaway VM
