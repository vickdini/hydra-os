#!/bin/bash
# wave11 GD: GTK programs (Firefox's title bar and buttons, GTK dialogs) follow Plasma's
# Breeze theme. Runs as root inside the Ubuntu root of the pool (network needed for apt):
#   linux chroot /ubuntu /usr/bin/bash /path/gtk-breeze-inside.sh
# Installs breeze-gtk-theme (the GTK 2/3/4 Breeze theme) and kde-config-gtk-style (KDE's
# GTK settings module: at every login kded's gtkconfig writes the user's GTK settings,
# settings.ini, gtkrc and xsettingsd's, from Plasma's own), then sets Breeze as the
# system-wide default (/etc/gtk-3.0, /etc/gtk-4.0, the GSettings defaults GTK reads on
# Wayland) and for the live user and new users (/etc/skel).
set -e
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a
apt-get update -qq
apt-get install -y -q -o Dpkg::Use-Pty=0 breeze-gtk-theme kde-config-gtk-style
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
ls /usr/share/themes | tr '\n' ' '; echo
echo GTK-BREEZE-OK
