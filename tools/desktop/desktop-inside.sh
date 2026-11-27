#!/bin/bash
# wave11 GD: the image's desktop settings. Runs as root inside the Ubuntu root of the pool
# (network needed for apt):  linux chroot /ubuntu /usr/bin/bash /path/desktop-inside.sh
# 1. kwin_wayland gets CAP_SYS_NICE (as Ubuntu's kwin package sets it on Linux): kwin then
#    runs its compositor thread SCHED_RR, which Hydra's scheduler runs at high priority, so
#    pointer moves and frames do not wait behind busy programs (Firefox).
# 2. GTK programs (GTK dialogs, Firefox's menus and widgets) follow Plasma's Breeze theme.
# 3. Firefox uses KDE's own title bar (KWin's Breeze decoration with its usual buttons)
#    instead of drawing one itself (its client-side buttons showed no glyph).
# Installs breeze-gtk-theme (the GTK 2/3/4 Breeze theme) and kde-config-gtk-style (KDE's
# GTK settings module: at every login kded's gtkconfig writes the user's GTK settings,
# settings.ini, gtkrc and xsettingsd's, from Plasma's own), then sets Breeze as the
# system-wide default (/etc/gtk-3.0, /etc/gtk-4.0, the GSettings defaults GTK reads on
# Wayland) and for the live user and new users (/etc/skel).
set -e
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a
apt-get update -qq
apt-get install -y -q -o Dpkg::Use-Pty=0 breeze-gtk-theme kde-config-gtk-style libcap2-bin librsvg2-common
# (librsvg2-common: GTK's SVG image loader; without it symbolic icons, the title-bar
# buttons' glyphs among them, do not draw)
ls /usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/ | xargs echo
setcap cap_sys_nice+ep /usr/bin/kwin_wayland
getcap /usr/bin/kwin_wayland
S='[Settings]
gtk-theme-name=Breeze
gtk-icon-theme-name=breeze
gtk-cursor-theme-name=breeze_cursors
gtk-cursor-theme-size=24
gtk-font-name=Noto Sans,  10
gtk-application-prefer-dark-theme=false
gtk-decoration-layout=icon:minimize,maximize,close
gtk-enable-animations=true
gtk-primary-button-warps-slider=true'
for d in /etc/gtk-3.0 /etc/gtk-4.0; do mkdir -p $d; printf '%s\n' "$S" > $d/settings.ini; done
printf '%s\n' "[org.gnome.desktop.interface]" "gtk-theme='Breeze'" "icon-theme='breeze'" "cursor-theme='breeze_cursors'" \
  "[org.gnome.desktop.wm.preferences]" "button-layout='icon:minimize,maximize,close'" > /usr/share/glib-2.0/schemas/90_hydra-breeze.gschema.override
glib-compile-schemas /usr/share/glib-2.0/schemas
for h in /etc/skel /home/hydra; do
  [ -d $h ] || continue
  for v in 3.0 4.0; do mkdir -p $h/.config/gtk-$v; printf '%s\n' "$S" > $h/.config/gtk-$v/settings.ini; done
done
chown -R hydra:hydra /home/hydra/.config/gtk-3.0 /home/hydra/.config/gtk-4.0 2>/dev/null || true
for d in /usr/lib/firefox /usr/lib/firefox-esr; do
  [ -d $d ] || continue
  mkdir -p $d/defaults/pref
  printf '%s\n' '// Hydra: KDE draws the title bar (Breeze), Firefox does not draw its own' 'pref("browser.tabs.inTitlebar", 0);' > $d/defaults/pref/hydra-desktop.js
done
ls /usr/share/themes | tr '\n' ' '; echo
echo DESKTOP-SETTINGS-OK
