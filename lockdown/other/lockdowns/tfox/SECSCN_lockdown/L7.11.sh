#!/bin/bash
# To resolve SECSCN test L7.11
# Description:
#  Check the icmp_echo_ignore_broadcasts setting

/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts=1

