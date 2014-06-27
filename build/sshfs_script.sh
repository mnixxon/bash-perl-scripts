#!/bin/bash

# This script will mount a remote directory to the user's home directory
# using sshfs.
#
# Dependencies
# Must have fuse-sshfs package installed

SERVER=blackfoot

function error_exit
{
  echo "$0: $1" 1>&2
  echo "Aborting"
}

#zenity --question --title "sshfs_script" --text "Mount your ROSE home directory to /home/$USER/${USER}_rose ?"
echo -e "Mount ROSE home dir to /home/$USER/${USER}_rose (Y/n)?"
read answer

if [ "$answer" != "y" -a "$answer" != "Y" ]; then
  exit 1
fi

#if [ $? = 1 ]; then
#  exit 1
#fi

#zenity --title "Password" --entry --text "[sudo] password for ${USER}: "
#read PASSWORD

mkdir -p /home/$USER/${USER}_rose

sudo sshfs -o allow_other ${USER}@${SERVER}:/home/$USER /home/$USER/${USER}_rose 

# To run this upon user login to GNOME, add a service to System --> Preferences --> Startup Applications
# Create a new service, call it 'Rose automount' and make this the command:
# gnome-terminal -e "bash -c \"/home/jhaas/bash-perl-scripts/build/sshfs_script.sh; exec bash\""
