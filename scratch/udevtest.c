/* udevtest: what libudev (as KWin and libinput use it) sees of Hydra's devices. */
#include <stdio.h>

struct udev;
struct udev_enumerate;
struct udev_list_entry;
struct udev_device;
struct udev_monitor;
struct udev *udev_new(void);
struct udev_enumerate *udev_enumerate_new(struct udev *);
int udev_enumerate_add_match_subsystem(struct udev_enumerate *, const char *);
int udev_enumerate_add_match_sysname(struct udev_enumerate *, const char *);
int udev_enumerate_scan_devices(struct udev_enumerate *);
struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *);
struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *);
const char *udev_list_entry_get_name(struct udev_list_entry *);
const char *udev_list_entry_get_value(struct udev_list_entry *);
struct udev_device *udev_device_new_from_syspath(struct udev *, const char *);
const char *udev_device_get_devnode(struct udev_device *);
const char *udev_device_get_subsystem(struct udev_device *);
const char *udev_device_get_sysname(struct udev_device *);
const char *udev_device_get_property_value(struct udev_device *, const char *);
const char *udev_device_get_sysattr_value(struct udev_device *, const char *);
int udev_device_get_is_initialized(struct udev_device *);
struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *);
struct udev_device *udev_device_get_parent_with_subsystem_devtype(struct udev_device *, const char *, const char *);
struct udev_monitor *udev_monitor_new_from_netlink(struct udev *, const char *);
int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *, const char *, const char *);
int udev_monitor_enable_receiving(struct udev_monitor *);

static void list(struct udev *u, const char *subsystem, const char *sysname) {
    struct udev_enumerate *e = udev_enumerate_new(u);
    udev_enumerate_add_match_subsystem(e, subsystem);
    if (sysname)
        udev_enumerate_add_match_sysname(e, sysname);
    int r = udev_enumerate_scan_devices(e);
    printf("[udevtest] scan %s %s -> %d\n", subsystem, sysname ? sysname : "", r);
    for (struct udev_list_entry *it = udev_enumerate_get_list_entry(e); it; it = udev_list_entry_get_next(it)) {
        const char *path = udev_list_entry_get_name(it);
        struct udev_device *d = udev_device_new_from_syspath(u, path);
        printf("[udevtest]   %s\n", path);
        if (!d) {
            printf("[udevtest]     new_from_syspath failed\n");
            continue;
        }
        printf("[udevtest]     sysname=%s subsystem=%s devnode=%s initialized=%d seat=%s\n", udev_device_get_sysname(d), udev_device_get_subsystem(d),
               udev_device_get_devnode(d), udev_device_get_is_initialized(d), udev_device_get_property_value(d, "ID_SEAT"));
        for (struct udev_list_entry *p = udev_device_get_properties_list_entry(d); p; p = udev_list_entry_get_next(p))
            printf("[udevtest]     %s=%s\n", udev_list_entry_get_name(p), udev_list_entry_get_value(p));
        struct udev_device *pci = udev_device_get_parent_with_subsystem_devtype(d, "pci", NULL);
        if (pci)
            printf("[udevtest]     pci parent boot_vga=%s\n", udev_device_get_sysattr_value(pci, "boot_vga"));
    }
}

int main(void) {
    struct udev *u = udev_new();
    printf("[udevtest] udev_new %s\n", u ? "ok" : "FAILED");
    list(u, "drm", "card[0-9]");
    list(u, "input", NULL);
    struct udev_monitor *m = udev_monitor_new_from_netlink(u, "udev");
    printf("[udevtest] monitor %s", m ? "ok" : "FAILED");
    if (m) {
        udev_monitor_filter_add_match_subsystem_devtype(m, "drm", NULL);
        printf(", enable_receiving -> %d", udev_monitor_enable_receiving(m));
    }
    printf("\n[udevtest] done\n");
    return 0;
}
