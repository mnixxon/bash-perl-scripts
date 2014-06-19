#!/bin/bash
# To resolve SECSCN test L3.4
# Description:
#   Verify system/privileged accounts are disallowed ftp login privileges 

awk -F':' '$3>=0 && $3<=500 {print $1}' /etc/passwd > /etc/ftpusers 
