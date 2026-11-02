#!/bin/sh
# Debug wrapper: the greeter's compositor, with its output kept
exec kwin_wayland "$@" >>/tmp/greeter-kwin.log 2>&1
