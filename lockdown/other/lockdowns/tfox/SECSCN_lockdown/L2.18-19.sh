#!/bin/bash
# To resolve SECSCN test L2.18-19 
# Description:
# 	Verify nodev options are set properly in the /etc/fstab file.
# 	Verify nosuid options are set properly in the /etc/fstab file.

  sed -i -e '/ext/s/defaults /defaults,nodev,nosuid/' /etc/fstab
  sed -i -e '/ \/ /s/defaults,.*/defaults/' /etc/fstab
