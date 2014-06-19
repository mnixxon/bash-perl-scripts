#!/bin/bash
# To resolve SECSCN test L5.1
# Description:
#   	Verify root login is restricted to system console.

sed -e '/vc/d' /etc/securetty > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/securetty
