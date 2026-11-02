#!/bin/sh
# Debug wrapper: the greeter, with its output kept
echo "== greeter $* (WAYLAND_DISPLAY=$WAYLAND_DISPLAY XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR QT_QPA_PLATFORM=$QT_QPA_PLATFORM)" >>/tmp/greeter.log
/usr/bin/sddm-greeter-qt6.real "$@" >>/tmp/greeter.log 2>&1
echo "== exit $?" >>/tmp/greeter.log
