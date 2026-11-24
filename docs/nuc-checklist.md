# Trying Hydra on the NUC: a checklist

This is for the first test of Hydra on real hardware: the Intel NUC (2014, Core i5-4250U).
You need about an hour, a Windows PC, a USB stick of **8 GB or more** whose contents you
can lose, a USB keyboard and mouse, a screen, and the network cable.

**Important:** installing Hydra (part C) **erases the NUC's internal disk completely**. If
anything on it matters, copy it somewhere else first, or do only parts A, B and D (trying
Hydra from the stick changes nothing on the NUC).

Hydra writes a log of every start onto the stick. Whatever happens, the log is what we need
back (part D). Nothing you can do here can harm the NUC's hardware.

## A. Write the stick (on the Windows PC)

1. Download **Rufus** from <https://rufus.ie> (the "Portable" version needs no installation)
   and the Hydra stick image file `hydra-live.img` you were given.
2. Plug the USB stick into the PC. Start Rufus.
3. **Device:** choose the USB stick. Check the name and size twice: everything on it will be
   erased.
4. **Boot selection:** click **SELECT** and choose `hydra-live.img`.
5. Click **START**. If Rufus asks how to write the image, choose **"Write in DD Image
   mode"**. Confirm that the stick will be erased. Wait until it says **READY** (a few
   minutes).
6. Windows may now show a drive named **HYDRA-LIVE**, and perhaps a message that another
   drive "needs to be formatted": **click Cancel. Never format it** (that part holds Hydra
   itself, Windows just cannot read it).
7. Eject the stick ("Safely remove") and unplug it.

## B. Prepare the NUC and start Hydra

1. **Unplug the USB Wi-Fi adapter** from the NUC for this test (Hydra has no Wi-Fi yet).
   Please write down its brand and model (printed on it, or in Windows' Device Manager),
   we need it later. (If you leave it in, Hydra ignores it and notes its ID in the log.)
2. **Plug the network cable into the NUC before switching it on.**
3. Plug in the Hydra stick, the keyboard, the mouse and the screen.
4. Switch the NUC on and **press F2** repeatedly until the setup screen ("Visual BIOS")
   appears. Check these settings (names differ a little between versions; leave everything
   else as it is):
   - **Boot > Secure Boot: off** (Disabled). Hydra is not signed for Secure Boot.
   - **Boot > UEFI Boot: on.** (Legacy boot may stay on.)
   - **Boot > Fast Boot: off** (so the NUC sees the stick and the F10 key).
   - **Advanced > Security** (or **Performance > Processor**): **Intel Virtualization
     Technology** and **Intel VT for Directed I/O (VT-d): on**, if they are listed.
   - Press **F10** to save and leave. The NUC restarts.
5. Right after switching on (or after the restart), **press F10** repeatedly: a boot menu
   appears. Choose the USB stick (its "UEFI" entry if there are two).
6. **What you should see:**
   - First a short text menu, **"Hydra - how to start"**, counting down 5 seconds. Do
     nothing: entry 1 starts by itself. (If it does not count down, press **1**.)
   - Then the Hydra logo with a spinning circle, for up to a minute or two.
   - Then the desktop with a window **"You are trying Hydra"**. This is the live session:
     it runs from the stick and changes nothing on the NUC.
7. **Check what works**, and note each result (works / does not):
   - The mouse pointer moves and the keyboard types (open the start menu and type).
   - **Network:** open Firefox (the fox icon in the bottom bar) and visit a web page such
     as `en.wikipedia.org`. If it does not load within a minute, note "no network".
   - **Sound:** plug headphones into the NUC's front jack; in the start menu search for
     "System Settings", open "Sound", and press the "Test" button.
8. To finish without installing: start menu > **Shut Down**. At the end the screen turns
   black with the line **"Hydra has stopped. Remove the installation stick (USB), then press
   Enter."** Remove the stick then (or press Enter): the NUC switches off.

## C. Install Hydra on the NUC (erases the NUC's disk)

1. Start the stick again as in B.5. In the "You are trying Hydra" window click **Install
   Hydra** (or the "Install Hydra" icon on the desktop).
2. Follow the pages: language, keyboard, **the disk** (the NUC's internal disk: check that its
   size matches it, and never choose the USB stick), your name and password. Confirm that the
   disk will be erased.
3. Copying takes about 5 to 10 minutes. At the end click **Restart now**. When the black
   screen asks for it, remove the stick and press Enter (if you already pulled the stick
   earlier, Hydra restarts by itself now).
4. The NUC now starts Hydra from its own disk: the same short menu (3 seconds), the logo, then
   the login screen. Log in with the name and password you chose. Repeat the checks of
   B.7 (mouse, keyboard, Firefox, sound).
5. Restart once from the start menu (**Restart**) and log in again.

Note: Hydra runs **offline** too. Without a network it starts normally, only web pages
and other languages than English (downloaded on first start) are missing.

## D. If something goes wrong, and sending the logs

**If the screen stays on the logo for more than 5 minutes,** or freezes: wait one more
minute, then hold the power button for 5 seconds to switch off. Then start the stick again
with **F10**, and in the "how to start" menu press **2** (safe mode: one processor,
no IOMMU, boot messages on screen). If that also stops, take a **photo of the screen**, and
try entry **3** (safe mode, text console only).

**If the screen shows "KERNEL PANIC"** (red text): take a photo. Hydra restarts by itself
after 60 seconds to save its log; choose the stick again with F10 so it can write the log
(otherwise the NUC starts the other system and the log is lost).

**Collecting the logs:**
1. If you tested the installed system (part C): start the stick once more (F10, entry 1)
   and simply shut it down again. On the way it copies the installed system's logs onto the
   stick (`logs\disk`).
2. Plug the stick into the Windows PC. Open the drive **HYDRA-LIVE**, then the folder
   **logs**. Every start left a file `boot001.txt`, `boot002.txt`, ... (the highest number
   is the newest); the folder `disk` holds the installed system's ones.
3. Right-click the **logs** folder > "Send to" > "Compressed (zipped) folder", and send that
   zip file, your notes from B.7 / C.4, any photos and the Wi-Fi adapter's model back.
4. Eject the stick safely before unplugging it.

## For the developers: what the stick does

- Start menu: `\hydra\menu` (`timeout=N`) on the EFI partition; entry 2 adds the boot words
  `safe iommu=off pcid=off cpus=1 verbose`, entry 3 also `nodesktop`. Extra words can be
  put into `\hydra\options.txt` (one or more per line, `#` comments) from any computer.
- Boot log: `\logs\bootNNN.txt` (2,162,688 bytes each, the last 10 kept): created before
  `ExitBootServices` through the firmware, then rewritten in place every 20 s and at
  power-off/restart; after a kernel panic (or when the pool's disk never came) the log stays
  in memory, the machine restarts after 60 s and the next start writes it into the old
  file. See `src/arch/bootlog.rs`.
- The network is not needed: the boot waits at most 10 s for DHCP; the first-boot language
  download runs in the background and gives up after 10 minutes.
