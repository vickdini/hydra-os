TOOLKIT (Group B, stable): Python 3 + PyQt6 with Qt Widgets (packages python3-pyqt6, from Ubuntu universe). Reason: PySide6 pulls libshiboken6 -> libclang1-21 (+LLVM); PyQt6 is ~17 MB with no compiler libs; Qt Widgets get KDE's Breeze style, so windows look like other KDE apps; no QML/Kirigami needed. Hydra installs python3-pyqt6 itself if missing (see below).
Now: setting up a dev VM and checking what the pool has (python3, PyQt6, polkit, sysusers).
Works: -
Next: Hydra Apps store (catalogue + PyQt6 window + root helper via pkexec), Windows shortcuts, sysusers at boot, first-login welcome.
