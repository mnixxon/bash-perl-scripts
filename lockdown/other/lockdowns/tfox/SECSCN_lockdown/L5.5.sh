#/bin/bash
# To resolve SECSCN test L5.5
# Description:
# Ensure X server is configured to prevent listening on port 6000/tcp   	

sed -i -e '/security/aDisallowTCP=true'   /etc/gdm/custom.conf
