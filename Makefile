TARGET := x86_64-unknown-uefi
EFI_BIN := target/$(TARGET)/release/hydra.efi
DIST_DIR := dist/x86_64
IMG := $(DIST_DIR)/hydra.img
STORAGE_IMG := $(DIST_DIR)/storage.img
ISO := $(DIST_DIR)/kernel.iso

.PHONY: all build clean rootfs-media userland

all: build

# Linux userland pieces installed into the Ubuntu root by `linux chroot` (needs libdbus-1-dev)
LOGIND := esp/bin/hydra-logind.elf
userland: $(LOGIND)

$(LOGIND): userland/hydra-logind/hydra-logind.c
	mkdir -p esp/bin
	gcc -O2 -Wall -o $@ $< -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -ldbus-1
	strip $@

$(EFI_BIN):
	cargo build --release --target $(TARGET)

build: $(EFI_BIN) $(LOGIND)
	mkdir -p $(DIST_DIR)
	@if [ ! -f $(STORAGE_IMG) ]; then \
		echo "Creating persistent 32MB ATA storage image..."; \
		dd if=/dev/zero of=$(STORAGE_IMG) bs=1M count=32; \
	fi
	cp $(EFI_BIN) $(DIST_DIR)/bootx64.efi
	# Create FAT EFI disk image (16MB; El Torito limits the boot image size)
	dd if=/dev/zero of=$(IMG) bs=1M count=16
	mkfs.vfat $(IMG)
	mmd -i $(IMG) ::/EFI ::/EFI/BOOT ::/bin ::/apps
	mcopy -i $(IMG) $(DIST_DIR)/bootx64.efi ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $(IMG) esp/readme.txt ::/README.TXT
	mcopy -i $(IMG) esp/bin/* ::/bin/
	# Create bootable UEFI ISO with El Torito EFI boot catalog
	rm -rf $(DIST_DIR)/iso_root
	mkdir -p $(DIST_DIR)/iso_root/EFI/BOOT $(DIST_DIR)/iso_root/bin $(DIST_DIR)/iso_root/apps
	cp $(DIST_DIR)/bootx64.efi $(DIST_DIR)/iso_root/EFI/BOOT/BOOTX64.EFI
	cp esp/readme.txt $(DIST_DIR)/iso_root/README.TXT
	cp -r esp/bin/* $(DIST_DIR)/iso_root/bin/
	cp $(IMG) $(DIST_DIR)/iso_root/efiboot.img
	xorriso -as mkisofs -V "HYDRA" -e efiboot.img -no-emul-boot -isohybrid-gpt-basdat -o $(ISO) $(DIST_DIR)/iso_root
	rm -rf $(DIST_DIR)/iso_root

# Installation media: a FAT32 disk holding root filesystem archives from esp/rootfs.
# Attach it as a second disk; `linux rootfs install` finds \rootfs\ubuntu-base.tar.gz on it.
rootfs-media:
	mkdir -p $(DIST_DIR)
	dd if=/dev/zero of=$(DIST_DIR)/rootfs-media.img bs=1M count=256
	mkfs.vfat -F 32 -n HYDRAINST $(DIST_DIR)/rootfs-media.img
	mmd -i $(DIST_DIR)/rootfs-media.img ::/rootfs
	mcopy -i $(DIST_DIR)/rootfs-media.img esp/rootfs/* ::/rootfs/

clean:
	cargo clean
	rm -rf $(DIST_DIR)

docs-pdf:
	python3 scripts/generate_docs_pdf.py || python scripts/generate_docs_pdf.py

