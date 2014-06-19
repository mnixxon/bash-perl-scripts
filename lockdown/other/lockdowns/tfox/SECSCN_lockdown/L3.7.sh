#!/bin/bash
# To resolve SECSCN test L3.7
# Description:
#   Check for GUI Login 

sed 's/id:5:initdefault:/id:3:initdefault:/' /etc/inittab > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/inittab

