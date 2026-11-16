// Written by Hydra: the desktop a new user starts with, laid out like Windows 11's. One panel
// at the bottom: the start menu and the programs (pinned and running) in the middle, between
// two flexible spacers (Plasma centres what lies between two of them), then the notification
// area, the clock and the "show desktop" corner on the right. The classic KDE layout stays a
// click away: System Settings > Colours & Themes > Global Theme > Breeze.
var panel = new Panel
panel.location = "bottom"
// Windows 11's taskbar is 48 pixels at 100 % scaling
panel.height = 2 * Math.ceil(gridUnit * 2.5 / 2)

panel.addWidget("org.kde.plasma.panelspacer")

var start = panel.addWidget("org.kde.plasma.kickoff")
start.currentConfigGroup = ["General"]
// The start menu opens on the pinned programs, shown as a grid as on Windows
start.writeConfig("favoritesDisplay", 0)
start.writeConfig("applicationsDisplay", 1)

var tasks = panel.addWidget("org.kde.plasma.icontasks")
tasks.currentConfigGroup = ["General"]
// Pinned like Windows' taskbar: File Explorer, the browser, the store (Hydra Apps) and Settings
tasks.writeConfig("launchers", ["applications:org.kde.dolphin.desktop", "preferred://browser",
                                "applications:org.hydra.apps.desktop", "applications:systemsettings.desktop"])

panel.addWidget("org.kde.plasma.panelspacer")

// Input methods for the languages that need one, as Plasma's own default panel does
var langIds = ["as", "bn", "bo", "brx", "doi", "gu", "hi", "ja", "kn", "ko", "kok", "ks", "lep", "mai", "ml",
               "mni", "mr", "ne", "or", "pa", "sa", "sat", "sd", "si", "ta", "te", "th", "ur", "vi", "zh_CN", "zh_TW"]
if (langIds.indexOf(languageId) != -1) {
    panel.addWidget("org.kde.plasma.kimpanel")
}
panel.addWidget("org.kde.plasma.systemtray")
var clock = panel.addWidget("org.kde.plasma.digitalclock")
clock.currentConfigGroup = ["Appearance"]
// Time above the date, as on Windows
clock.writeConfig("dateDisplayFormat", "BelowTime")
panel.addWidget("org.kde.plasma.showdesktop")

var desktopsArray = desktopsForActivity(currentActivity())
for (var j = 0; j < desktopsArray.length; j++) {
    desktopsArray[j].wallpaperPlugin = 'org.kde.image'
}
