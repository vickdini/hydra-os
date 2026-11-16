# Written by Hydra: Windows' keyboard shortcuts, set for each user once, before the desktop
# starts (Plasma runs the scripts in /etc/xdg/plasma-workspace/env/ at the start of a session).
# Plasma's shortcut daemon keeps every user's shortcuts in ~/.config/kglobalshortcutsrc and has
# no system-wide file for them, so the Windows ones are written there. Plasma already has most
# of Windows' (Win+E File Explorer, Win+D desktop, Win+L lock, Win+I Settings, Win+Left/Right
# snap, Win+Shift+S screenshot, Win+V clipboard); this adds
#   Win+Up    maximize (KDE: tile to the top half)
#   Win+Down  minimize (KDE: tile to the bottom half)
#   Win+R     Run (KRunner; KDE: Spectacle's screen recording, which keeps Win+Shift+R)
# A shortcut the user has changed is left alone, and each user gets this only once (a later
# change of theirs stays).
(
    command -v kwriteconfig6 > /dev/null || exit 0
    rc=hydra-desktoprc
    [ "$(kreadconfig6 --file $rc --group Shortcuts --key Windows)" = 1 ] && exit 0
    T=$(printf '\t')
    # set_sc KEY KDE_DEFAULT NEW GROUP...: NEW, unless the user changed KEY from KDE's default
    set_sc() {
        key=$1 kde=$2 new=$3
        shift 3
        cur=$(kreadconfig6 --file kglobalshortcutsrc "$@" --key "$key")
        if [ -z "$cur" ] || [ "${cur%%,*}" = "$kde" ]; then
            kwriteconfig6 --file kglobalshortcutsrc "$@" --key "$key" "$new"
        fi
    }
    set_sc "Window Maximize" "Meta+PgUp" "Meta+Up${T}Meta+PgUp,Meta+PgUp,Maximize Window" --group kwin
    set_sc "Window Quick Tile Top" "Meta+Up" "none,Meta+Up,Quick Tile Window to the Top" --group kwin
    set_sc "Window Minimize" "Meta+PgDown" "Meta+Down${T}Meta+PgDown,Meta+PgDown,Minimize Window" --group kwin
    set_sc "Window Quick Tile Bottom" "Meta+Down" "none,Meta+Down,Quick Tile Window to the Bottom" --group kwin
    set_sc RecordRegion "Meta+Shift+R${T}Meta+R" "Meta+Shift+R" --group services --group org.kde.spectacle.desktop
    set_sc _launch "Alt+Space${T}Alt+F2${T}Search" "Meta+R${T}Alt+Space${T}Alt+F2${T}Search" --group services --group org.kde.krunner.desktop
    kwriteconfig6 --file $rc --group Shortcuts --key Windows 1
)
