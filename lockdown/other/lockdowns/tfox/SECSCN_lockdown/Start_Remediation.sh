#!/bin/bash
# Timothy Fox 02.14.2013
#
#
# Script should only be run by Sysadmins of the network this is running on
#  
# Function:  
#	This script runs remediation for each of the tests called out by SECSCN 6.3
#	It is intended to be run only on a Boeing CSULI imaged machine and after
#	it has been brought into compliance with the STIG for RHEL5 by the Aqueduct
#	scripts provided in these directories.
#

# We need the script to be verbose since it asks for user input.
LOUD=true
IGNORE=false

SCRIPTZ=$( ls -1  *.sh | grep -vi Start )

while getopts "i:v" opt
do
        case $opt in
                v)
                        LOUD=true
                        ;;
                i)
                        IGNORE_FILE=$OPTARG
                        if [ -r "$IGNORE_FILE" ]
                        then
                                        IGNORE=true
                        else
                                echo "Cannot read $IGNORE_FILE"
                                exit
                        fi
                        ;;
                \?)
                        echo "Usage: $0 -v -i ignore_file"
                        exit
                        ;;
        esac
done

echo "$SCRIPTZ"

for file in $SCRIPTZ
  do
        if  ! $IGNORE   || ! grep -q $file $IGNORE_FILE
        then
                if  $LOUD
            then
                        # I have no idea why the extra stuff is there.
                        # It makes things hard to move to a document.
                # echo -e "\e[00;32mEXECUTING $file\e[00m"
                        echo "EXECUTING $file"
                        ./$file
                else
                        # echo "Quietly executing $file"
                        ./$file > /dev/null 2>&1
                fi
        fi

done
