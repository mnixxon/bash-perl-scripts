#!/bin/bash
# To resolve SECSCN test L2.3	
# Description:
#  Ensure lilo/grub password is set 

echo "Enter the system's GRUB password appropriate for this network"
MD5PASSWD=Sorry
while [ $MD5PASSWD = Sorry ]; do 
        /sbin/grub-md5-crypt 2>&1 | tee /tmp/grubpwd
        MD5PASSWD=`tail -1 /tmp/grubpwd | awk -F, '{print $1}'`
done

MD5PASSWD=`tail -1 /tmp/grubpwd`
TEST=`grep "password" /etc/grub.conf`
if [ "$TEST" == "" ];then
        sed -i -e '/hiddenmenu/apassword --md5 '"$MD5PASSWD"''  /boot/grub/grub.conf 
else
        sed -e '/password --md5/d'   /boot/grub/grub.conf > /tmp/tmp_hard
        cp -f /tmp/tmp_hard   /boot/grub/grub.conf
        sed -i -e '/hiddenmenu/apassword --md5 '"$MD5PASSWD"''  /boot/grub/grub.conf
fi

rm -f /tmp/grubpwd
