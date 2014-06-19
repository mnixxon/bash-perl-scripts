#!/bin/sh

# set variables
RHELVER=`uname -r`
ORACLE_SERVER="server15"
LH3USER_DATA_AGING_SERVER="server16"
VSFTPD_SERVER="server15"

#(FOUO)
#4.B.3.a(2) [Access2]
# Synopsis: Access control, including  Discretionary Access Control (DAC)
#          Policy. A system has implemented DAC when the Security
#          Support Structure defines and controls access between named
#          users and named objects in the System....These access controls
#          shall be capable of including or excluding access t the 
#          granularity of a single user.
#
# KickStart Actions: All ext3 file systmes have been mounted with the ACL
#                   setting to allow for a finer granualrity of DAC.
#                   (See:  getfacl and setfacl man pages).
#                   Create ACL and other security features during
#                   the mounting of each file system (/etc/fstab).

	if [ -e /etc/fstab.nolock ] ; then
		echo "File exists"
	else
		cp -p /etc/fstab /etc/fstab.nolock

		FSTAB=/etc/fstab
		SED=/bin/sed

		#nosuid and acl on /sys
		if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nosuid,acl/" ${FSTAB}
		fi

		#nosuid and acl on /boot
		if [ $(grep " \/boot " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/boot " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/boot.*${MNT_OPTS}\)/\1,nosuid,nodev,acl/" ${FSTAB}
		fi

		#nosuid and acl on /var
		if [ $(grep " \/var " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/var " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/var .*${MNT_OPTS}\)/\1,nosuid,nodev,acl/" ${FSTAB}
		fi
		
        #nosuid and acl on /var/security
		if [ $(grep " \/var\/security " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/var\/security " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/var\/security .*${MNT_OPTS}\)/\1,nosuid,nodev,acl/" ${FSTAB}
		fi
		
        #nodev and acl on /usr
		if [ $(grep " \/usr " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/usr " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/usr.*${MNT_OPTS}\)/\1,nodev,acl/" ${FSTAB}
		fi

		#REMOVED DUE TO "LINE XX IS BAD" ERROR MESSAGE WHEN APPENDING THIS
		#nodev and acl on /home
		#if [ $(grep " \/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
		#        MNT_OPTS=$(grep " \/home " ${FSTAB} | awk '{print $4}')
		#        ${SED} -i "s/\( \/home.*${MNT_OPTS}\)/\1,nodev,acl/" ${FSTAB}
		#fi

		#nodev and acl on /usr/local
		if [ $(grep " \/usr\/local " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	        	MNT_OPTS=$(grep " \/usr\/local " ${FSTAB} | awk '{print $4}')
	        	${SED} -i "s/\( \/usr\/local.*${MNT_OPTS}\)/\1,nodev,acl/" ${FSTAB}
		fi
	fi

#(FOUO)
#4.B.3.a(3) [Access3]
#Synopsis: Access Control, including: 
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.a(3)(a)
   #Synopsis: Some process or mechanism(s) that allow users (or processes acting
   #          on their behalf) to determine the formal access approvals.  This
   #          process or mechanism is intended to aid the user in determining
   #          the appropriateness of information exchange.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(3)(b)
   #Synopsis: Some process or mechanism(s) that allow users (or processes acting
   #          on their behalf) to determine the sensitivity level of data.  This
   #          process or mechanism is intended to aid the user in determining 
   #          the appropriateness of information exchange.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.a(4) [AcctMan]
#Synopsis: Account Management procedures that include: 
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.a(4)(a)
   #Synopsis: Identifying types of accounts (individual and group, conditions
   #          for group membership, associated privileges). 
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(4)(b)
   #Synopsis: Establishing an account (i.e., required paperwork and processes).
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(4)(c)
   #Synopsis: Activiating an account. 
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(4)(d)
   #Synopsis: Modifying an account (e.g., disabling an account, changing
   #          privilege level, group memberships, authenticators).
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(4)(e)
   #Synopsis: Terminating an account (i.e., processes and assurances). 
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.a(5) [Audit1]
#Synopsis: Auditing procedures, including: 
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.a(5)(a)
   #Synopsis:  Provide the capability to ensure that all audit records
   #           include enough info to allow the ISSO to determine the date and
   #           and time of the action, the system local of the action, the 
   #           system entity that initiated or completed the action, the
   #           resources involved, and the action involved. This is done by 
   #           default with syslog in Red Hat.
   #
   #KickStart Actions: None

   #/var/{run,log}/{utmp,wtmp} permission settings
   if [ -e /etc/rc.d/rc.sysinit.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/rc.d/rc.sysinit /etc/rc.d/rc.sysinit.nolock

   	perl -npe 's%chmod 0664 /var/run/utmp /var/log/wtmp%chmod 0644 /var/run/utmp /var/log/wtmp%g' -i /etc/rc.d/rc.sysinit
   fi

   #(FOUO)
   #4.B.3.a(5)(c)
   #Synopsis:  Maintain collected audit data at least 5 years and
   #           review at least weekly.
   #
   #KickStart Actions: Log rotation to 90 days (12 weeks) and turn compression on.
   #                   This will have to up'd if system does not retain backups
   #                   for 5 years  (e.g., tape backup).

   if [ -e /etc/logrotate.conf.nolock ] ; then
   	echo "File exists"
   else
        cp -p /etc/logrotate.conf /etc/logrotate.conf.nolock

	perl -npe 's/rotate\s+4/rotate 12/' -i /etc/logrotate.conf
      	perl -npe 's/\#compress/compress/' -i /etc/logrotate.conf
   fi

   # Rotate the audit-logs on a daily basis--keep them all
   if [ -e /etc/logrotate.d.audit.nolock ] ; then
   	echo "File exists"
   else
        cp -p /etc/logrotate.d/audit /etc/logrotate.d.audit.nolock

cat <<EOF > /etc/logrotate.d/audit
/var/log/audit/audit.log 
{
    daily
    notifempty
    missingok
    postrotate
    /sbin/service auditd restart 2> /dev/null > /dev/null || true
    endscript
}
EOF
   fi

   #(FOUO)
   #4.B.3.a(5)(d)
   #Synopsis: The system creates and maintains an audit trail
   #          that includes selected records of: 
   #
   #KickStart Actions: Turn on the Audit Daemon and set permissions
   /sbin/chkconfig auditd on
   /sbin/chkconfig --level 1 auditd on
   #Reset permissions on audit logs
   chmod 700 /var/log/audit
   chmod 600 /var/log/audit/*

#(FOUO)
#4.B.3.a(6) [Audit3]
#Synopsis:  Audit procedures that include the existence and use of audit
#           reduction and analysis tools.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(7) [Audit4]
#Synopsis:  An audit trail, created and maintained by the IS, that is
#           capable of recording changes to the mechanism's list of user
#           formal access permissions.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(8) [Audit5]
#Synopsis:  Audit Procedures, including:
#
#KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(8)(a)
   #Synopsis:  Individual accountability (i.e., unique identification of each
   #           user and association of that identity with all auditable actions
   #           taken by that individual).
   #
   #KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(8)(b) 
   #Synopsis:  Periodic testing by the ISSO or ISSM of the security posture of
   #           the IS by employing various intrusion/attack detection and 
   #           monitoring tools. These tools shall build upon audit reduction
   #           and analysis tools to aid the ISSO or ISSM in the monitoring
   #           and detection of suspicious, intrusive, or attack-like behavior
   #           patterns.
   #
   #KickStart Actions:  None

#(FOUO)
#4.B.3.a(9) [I&A2]
#Synopsis: An Identification and Authentication managment mechanism that
#          ensures a unique identifier for each user and that associates that
#          identifier with all auditable actions taken by ther user. 
#
#KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(9)(a)
   #Synopsis: Initial authenticator content and administrative procedures for
   #          initial authenticator distribution.
   #
   #KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(9)(b)
   #Synopsis: Individual and Group authenticators. (Group authenticators may only
   #          be used in conjuction withthe use of an individual/unique
   #          authenticator, that is, indivuals must be authenticated with an
   #          individual authenticator prior to use of a group athenticator).
   #
   #KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(9)(c)
   #Synopsis: Length, composition, and generation of authenticators.
   #
   #KickStart Actions: The following item have been set to meet this policy. 

   #Note:
   #Investigating using PAM for preventing 10 recent passwords- doesn't appear
   #to be easily done using pam_passwdqc

   #Passwd strength
#   if [ -e /etc/pam.d/system-auth.nolock ] ; then
#   	echo "File exists"
#   else
#   	cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.nolock
#cat <<EOF > /etc/pam.d/system-auth
#%PAM-1.0
#This file is auto-generated.
#User changes will be destroyed the next time authconfig is run.
#auth        required      pam_env.so
#auth        sufficient    pam_unix.so likeauth nullok
#auth        required      pam_deny.so
#auth	       required	     pam_tally.so onerr=fail no_magic_root
#
#account     required      pam_unix.so
#account     sufficient    pam_succeed_if.so uid < 100 quiet
#account     required      pam_permit.so
#account     required      pam_tally.so deny=3 reset no_magic_root
#
#password    required      pam_passwdqc.so enforce=users 
#password    sufficient    pam_unix.so nullok use_authtok md5 shadow remember=10
#password    required      pam_deny.so
#
#session     required      pam_limits.so
#session     required      pam_unix.so
#EOF
#   fi

   # Password Strength Settings /etc/login.defs
   if [ -e /etc/login.defs.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/login.defs /etc/login.defs.nolock

   	perl -npe 's/PASS_MIN_LEN\s+5/PASS_MIN_LEN  8/' -i /etc/login.defs
   	perl -npe 's/PASS_WARN_AGE\s+7/PASS_WARN_AGE  14/' -i /etc/login.defs

   #STIG specifies using following, but it's not a valid parameter
   #PAM is set in Section 4.B.3.a(9)(c)
   #echo "PASSLENGTH 8" >> /etc/login.defs

   #(FOUO)
   #4.B.3.a(9)(d)
   #Synopsis: Change Processes (periodic in case of compromise)
   #
   #KickStart Actions:  None

   #(FOUO)
   #4.B.3.a(9)(e)
   #Synopsis: Aging of static authenticators.
   #
   #KickStart Actions: Change the password expiration time from undefined 
   #                   to 60 days. Users cannot change passwords more than
   #                   once a day.

   #Experation time to 60 days.
######### REMOVED PASSWORD EXPIRATION FROM ROOT  ###########
   #perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 180/' -i /etc/login.defs
   #chage -M 60 root

   #Ensure that the user cannot change their password more than once a day.
   perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 7/g' -i /etc/login.defs

   fi

   #(FOUO)
   #4.B.3.a(9)(f)
   #Synopsis: History of static authenticator changes, with assurance of
   #          non-replication of individual authenticators, per directions
   #          in approved SSP.
   #
   #KickStart Actions: opasswd file creation in /etc/security/opasswd 
   #                   for non-replication. 

   touch /etc/security/opasswd
   chmod 600 /etc/security/opasswd

   #(FOUO)
   #4.B.3.a(9)(g)
   #Synopsis: Protection of authenticators to perserve confidentiality and 
   #          integrity.  Red Hat encrypts authenticators using the MD5
   #          Message Digest.
   #
   #KickStart Actions: Additional I&A Security. 

#(FOUO)
#4.B.3.a(10) [I&A4]
#Synopsis: Identification and Authentication. In those instances where the
#          the means of authentication is user-specified passwords, the ISSO
#          or ISSm may employ (under the auspices of the DAA) automated tools
#          to validate that the passwords are sufficiently strong to resist
#          cracking and other attacks intended to discover a users password.
#
#KickStart Actions:  See 4.B.3.a(9)(c); specifically passwdqc

#(FOUO)
#4.B.3.a(11) [I&A5]
#Synopsis: Identification and Authentication.  In those instances where the
#          users are remotely accessing the system, the users shall employ
#          a strong authentication mechanism.  
#
#KickStart Actions: By default ssh uses Triple DES.  This script will edit
#                   the /etc/ssh/ssh_config file to use stronger encryption. 
# This section does not make sense because all the Ciphers are added
# in section 4.B.3.a(22)(a)(3). By specifying all the Ciphers the client
# can choose which one to use.  We also can't restrict only to aes256-cbc
# because the NetApp filers can only talk to 3des-cbc 

#(FOUO)
#4.B.3.a(12) [LeastPrv]
#Synopsis: Least Privilege procedures, including the assurance that each user
#          or process is granted the most restrictive set of privileges or
#          accesses needed for performance of authorized tasks shall be
#          employed.
#
#KickStart Actions: Restrict Root Logins and Least Privilege Enhancements.

# TODO ====== COMMENTING THIS OUT FOR NOW
#Further restricting root logins
#if [ -e /etc/pam.d/su.nolock ] ; then
#	echo "File exists"
#else
#	cp -p /etc/pam.d/su /etc/pam.d/su.nolock
#cat << EOF > /etc/pam.d/su
##%PAM-1.0
#auth       sufficient   pam_rootok.so
##Uncomment the following line to implicitly trust users in the "wheel" group.
##auth       sufficient   pam_wheel.so trust use_uid
##Uncomment the following line to require a user to be in the "wheel" group.
#auth       required     pam_wheel.so use_uid
#auth       required     pam_stack.so service=system-auth
#account    required     pam_stack.so service=system-auth
#password   required     pam_stack.so service=system-auth
##pam_selinux.so close must be first session rule
#session    required     pam_selinux.so close
#session    required     pam_stack.so service=system-auth
##pam_selinux.so open and pam_xauth must be last two session rules
#session    required     pam_selinux.so open multiple
#session    optional     pam_xauth.so
#EOF
#fi
# END TODO ==============================

# You have to enter a Superuser PW when booting into single user mode
if [ -e /etc/inittab.nolock ] ; then
	echo "File exists"
else
	cp -p /etc/inittab /etc/inittab.nolock

	echo "~~:S:wait:/sbin/sulogin" >> /etc/inittab
fi

#(FOUO)
#4.B.3.a(13) [Marking]
#Synopsis: Marking procedures and mechanisms to ensure that either the
#          user or the system itself marks all data transmitted or stored
#          by the system to reflect the sensitivity of the data.  Markings
#          shall be retained with the data.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(14) [ParamTrans]
#Synopsis: Parameter Transmission.  Security parameters shall be reliably
#          associated (either explicity or implicity) with information
#          exchanged between systems.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(15) [Recovery]
#Synopsis: Recovery procedures and technical system features to assure 
#          that system recovery is done in a trusted and secure manner.
#          If any circumstances can cause an untrusted recovery, such
#          Circumstances shall be documented and appropriate mitigating
#          procedures shall be put in place.
#
#KickStart Actions: Centralized Time

#(FOUO)
#4.B.3.a(16) [ResrcCtrl]
#Synopsis: Resource Control.  All authorizations to the information 
#          contained within an object shall be revoked prior to
#          initial assignment, allocation, or reallocation to a subject
#          from the Security Support Structure's pool of unused objects.
#          No information including encrypted representations of
#          information, produced by a subject's actions is to be
#          available to any subject that obtains access to an object
#          that has been released back to the system.  There must be no
#          residual data from the former object.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(17) [ScrnLck]
#Synopsis: Screen Lock.  Unless there is an overriding technical or
#          operational problem, a screen-lock functionality shall be 
#          associated with each computer.  When activated, a screen-lock
#          function shall place an unclassified pattern onto the entire
#          screen, totally hiding what was previously visible on the 
#          screen.  Such a capability shall:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.a(17)(a)
   #Synopsis: Be enabled either by explicit user action or if the system 
   #          is left idle for a specified period of time (e.g., 15 min
   #          or more).
   #
   #KickStart Actions: Interactive Shell setting here.

   #Gnome screen-saver line command tool -->  needs to be tested.
   #gconftool-2 --direct \
   #  --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
   #  --type int \
   #  --set /apps/gnome-screensaver/idle_delay 15

   #(FOUO)
   #4.B.3.a(17)(b)
   #Synopsis: Ensure that once the security/screen-lock sofware is 
   #          activated, access to the system requires knowledge of a 
   #          unique authenticator.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.a(17)(c)
   #Synopsis: Not be considered a substitute for logging out (unless a 
   #          mechanism actually logs out the user when the user idle
   #          time is exceeded.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.a(18) [Separation]
#Synopsis: Separation of Roles.  The functions of the ISSO and the 
#          System Administrator shall not be performed by the same 
#          person.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.a(19) [SessCtrl1]
#Synopsis: Session Controls, including:  
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.a(19)(a)
   #Synopsis: User notification such that all IS users shall be
   #          notified prior to gaining access to a system that system 
   #          usage may be monitored, recorded, and subject to audit.  
   #          Electronic means shall be employed where technically 
   #          feasible.
   #
   #KickStart Actions: See Section 4.B.3.a(19)(b)

#(FOUO)
   #4.B.3.a(19)(b)
   #Synopsis: The user shall also be advised that use of the system
   #          indicates (1) the consent of the user to such monitoring
   #          and recording and (2) that unauthorized use is prohibited
   #          and subject to criminal and civil penalities.  Electronic
   #          means shall be employed where technically feasible.
   #
   #KickStart Actions: Banner Settings

   #This part creates the same login banner once your username and password has 
   #been entered.  This has linefeeds in it.
   if [ "$RHELVER" = "2.6.9-89.ELsmp" ]; then
   if [ -e /etc/X11/gdm/PreSession/Default.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/X11/gdm/PreSession/Default /etc/X11/gdm/PreSession/Default.nolock
cat <<EOF >/etc/X11/gdm/PreSession/Default
#!/bin/sh
#
# Note that any setup should come before the sessreg command as
# that must be 'exec'ed for the pid to be correct (sessreg uses the parent
# pid)
#
# Note that output goes into the .xsession-errors file for easy debugging
#
PATH="/usr/bin/X11:/usr/X11R6/bin:/opt/X11R6/bin:$PATH:/bin:/usr/bin"

/usr/bin/gdialog --yesno "THIS IS A DEPARTMENT OF DEFENSE COMPUTER SYSTEM.  THIS COMPUTER 
SYSTEM, INCLUDING ALL RELATED EQUIPMENT, NETWORKS, AND NETWORK DEVICES (SPECIFICALLY 
INCLUDING INTERNET ACCESS), ARE PROVIDED ONLY FOR AUTHORIZED US GOVERNMENT USE.  DOD 
COMPUTER SYSTEMS MAY BE MONITORED FOR ALL LAWFUL PURPOSES, INCLUDING TO ENSURE THEIR 
USE IS AUTHORIZED, FOR MANAGEMENT OF THE SYSTEM, TO FACILITATE PROTECTION AGAINST 
UNAUTHORIZED ACCESS, AND TO VERIFY SECURITY PROCEDURES, SURVIVABILITY, AND OPERATIONAL 
SECURITY.  MONITORING INCLUDES ACTIVE ATTACKS BY AUTHORIZED DOD ENTITIES TO TEST OR 
VERIFY THE SECURITY OF THIS SYSTEM.  DURING MONITORING, INFORMATION MAY BE EXAMINED, 
RECORDED, COPIED, AND USED FOR AUTHORIZED PURPOSES.  ALL INFORMATION, INCLUDING PERSONAL 
INFORMATION, PLACED ON OR SENT OVER THIS SYSTEM, MAY BE MONITORED.

USE OF THIS DOD COMPUTER SYSTEM, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO 
MONITORING OF THIS SYSTEM.  UNAUTHORIZED USE MAY SUBJECT YOU TO CRIMINAL PROSECUTION.  
EVIDENCE OF UNAUTHORIZED USE COLLECTED DURING MONITORING MAY BE USED FOR ADMINISTRATIVE, 
CRIMINAL, OR OTHER ADVERSE ACTION.  USE OF THIS SYSTEM CONSTITUTES CONSENT TO MONITORING 
FOR THESE PURPOSES."
if ( test 1 -eq \$? ); then
	gdialog --infobox "Logging out in 10 Seconds" 1 20 &
	sleep 10
	exit 1
fi

gdmwhich () {
	COMMAND="$1"
	OUTPUT=
	IFS=:
	for dir in $PATH
	do
		if test -x "$dir/$COMMAND" ; then
			if test "x$OUTPUT" = "x" ; then
				OUTPUT="$dir/$COMMAND"
			fi
		fi
	done
	unset IFS
	echo "$OUTPUT"
}

XSETROOT=\`gdmwhich xsetroot\`
#if [ "x$XSETROOT" != "x" ] ; then
#	# Try to snarf the BackgroundColor from the config file
#	BACKCOLOR=`grep '^BackgroundColor' /etc/X11/gdm/gdm.conf | sed 's/^.*=\(.*\)$/\1/'`
#	if [ "x$BACKCOLOR" = "x" ]; then
#		BACKCOLOR="#76848F"
#	fi
#	"$XSETROOT" -cursor_name left_ptr -solid "$BACKCOLOR"
#fi

SESSREG=\`gdmwhich sessreg\`
if [ "x$SESSREG" != "x" ] ; then
	# some output for easy debugging
	echo "$0: Registering your session with wtmp and utmp"
	echo "$0: running: $SESSREG -a -w /var/log/wtmp -u /var/run/utmp -x \"$X_SERVERS\" -h \"$REMOTE_HOST\" -l \"$DISPLAY\" \"$USER\""

	exec "$SESSREG" -a -w /var/log/wtmp -u /var/run/utmp -x "$X_SERVERS" -h "$REMOTE_HOST" -l "$DISPLAY" "$USER"
	# this is not reached
fi
#Some output for easy debugging
echo "$0: could not find the sessreg utility, cannot update wtmp and utmp"
exit 0
EOF
   fi
   fi

#/etc/ssh/sshd_config X11Forwarding settings
if [ -e /etc/ssh/sshd_config_x11.nolock ] ; then
	echo "File exists"
else
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_x11.nolock
	perl -npe 's/X11Forwarding yes/X11Forwarding no/g' -i /etc/ssh/sshd_config
fi

#/etc/ssh/sshd_config banner settings
if [ -e /etc/ssh/sshd_config_banner.nolock ] ; then
	echo "File exists"
else
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_banner.nolock
	perl -npe 's/#Banner none/Banner \/etc\/issue/g' -i /etc/ssh/sshd_config
fi

#(FOUO) 
#4.B.3.a(20) [SessCtrl2] 
#Synopsis: Enforcement of Session Controls, including:  
#
#KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(20)(a)
   #Synopsis: Procedures for controlling and auditing concurrent logons from
   #          different workstations.
   #
   #KickStart Actions: None
   #(FOUO) 
   #4.B.3.a(20)(b)
   #Synopsis: Staton or session time-outs, as applicable.
   #
   #KickStart Actions: None

   #Set an inactive shell timeout - likely going away in March STIG
   if [ -e /etc/profile.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/profile /etc/profile.nolock

   	echo "TMOUT=900" >> /etc/profile

   #(FOUO) 
   #4.B.3.a(20)(c)
   #Synopsis: Limited retry on logon as technically feasible.
   #
   #KickStart Actions: None

   #Users get five attempts to enter their password each login attempt
   	echo "LOGIN_RETRIES 3" >> /etc/login.defs

   #Make the user wait four seconds if they fail after LOGIN_RETRIES
   	echo "FAIL_DELAY 900" >> /etc/login.defs
   fi

   #(FOUO) 
   #4.B.3.a(20)(d)
   #Synopsis: System actions on unsuccessful logons (e.g., blacklisting of
   #          the terminal or user identifier).
   #
   #KickStart Actions: None

#(FOUO) 
#4.B.3.a(21) [Storage] 
#Synopsis: Data Storage, implementing at least one of the following:
#
#KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(21)(a)
   #Synopsis: Information stored in an area approved for open storage of
   #          the information.
   #
   #KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(21)(b)
   #Synopsis: Information stored in an area for continuous personnel access
   #          control (24/7).
   #
   #KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(21)(c)
   #Synopsis: Information secured as appropriate for closed storage.
   #
   #KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(21)(d)
   #Synopsis: Information encrypted using NSA-approved encryption mechanisms
   #          appropriate for the classification of stored data.
   #
   #KickStart Actions: None

   #Will need to down load an encryption package like "secret agent"

#(FOUO) 
#4.B.3.a(22) [Trans1] 
#Synopsis: Data Transmission
#
#KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(22)(a)
   #Synopsis: Data transmission that implements at least one of the following.
   #
   #KickStart Actions: None

      #(FOUO) 
      #4.B.3.a(22)(a)(1)
      #Synopsis: Information distributed only within an area approved for
      #          open storage of the information.
      #
      #KickStart Actions: None

      #(FOUO) 
      #4.B.3.a(22)(a)(2)
      #Synopsis: Information distributed via a Proteced Distributed System
      #          (PDS).
      #
      #KickStart Actions: None

      #(FOUO) 
      #4.B.3.a(22)(a)(3)
      #Synopsis: Information distributed using NSA-approved encryption
      #          mechanisms appropriate for the classification of
      #          information.
      #
      #KickStart Actions:
      if [ -e /etc/ssh/ssh_config_crpyt.nolock ] ; then
      	   echo "File exists"
      else
      	   cp -p /etc/ssh/ssh_config /etc/ssh/ssh_config_crpyt.nolock

      	   echo 'Ciphers aes256-cbc,aes192-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,3des-cbc' >> /etc/ssh/ssh_config
      fi

      #(FOUO) 
      #4.B.3.a(22)(a)(4)
      #Synopsis: Information distributed using a trusted courier.
      #
      #KickStart Actions: None

   #(FOUO) 
   #4.B.3.a(22)(b)
   #Synopsis: Data lines, other than those that are protected with nationally
   #          certified crypographic devices or PDSs, shall not be used for 
   #          gaining access to system resources that process intelligence
   #          information unless the DAA provides specific written
   #          authorization for a system to operate in this manner.
   #
   #KickStart Actions: None

#(FOUO)
#DCID 6/3 PL3
#4.B.3 Protection Level 3
#4.B.3.b(1) [Doc1]
#Synopsis: Documentation shall include:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(1)(a)
   #Synopsis: A System Security Plan.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(1)(b)
   #Synopsis: SECCONOP.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.b(2) [Doc2]
#Synopsis: Documentation shall include guide(s) or manual(s) for the systems
#          privileged users (PUG).
#
#KickStart Actions: None


#(FOUO)
#4.B.3.b(3) [Doc3]
#Synopsis: Documentation shall include:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(3)(a)
   #Synopsis: Certification test plans and procedures detailing the
   #          implmentation of the features and assurances for the
   #          required Protection Level.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(3)(b)
   #Synopsis: Reports of test results.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(3)(c)
   #Synopsis: A general user's guide that describes the protection
   #          mechanisms provided, and that supplies guidlines on how
   #          the mechanisms are to be used, and how they interact.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.b(4) [SysAssur1]
#Synopsis: System Assurance shall include:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(4)(a)
   #Synopsis: Features and procedures to validate the integrity and the
   #          expected operation of the security-relevant software
   #          hardware, and firmware.
   #
   #KickStart Actions: Expected Operations

   #Max Number of Remembered Connection Requests
   if [ -e /etc/sysctl.conf.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/sysctl.conf /etc/sysctl.conf.nolock

   	echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf

   #ICMP ECHO Request Protection
   	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

   #Reject incoming packets if their source address doesn't match the 
   #network interface that they're arriving on, which helps to prevent 
   #IP spoofing
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf

   #Disables IP Source Routing
   	echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
   fi

   #This effectively prevents any non-root user from running traceroute
   chmod 700 /bin/traceroute

   #Turn off xinetd
   /sbin/chkconfig xinetd off

   # Turn off unneeded services
   /sbin/chkconfig bluetooth off
   /sbin/chkconfig cups off
   /sbin/chkconfig cups-config-daemon off
   /sbin/chkconfig irda off
   /sbin/chkconfig lm_sensors off
   /sbin/chkconfig portmap off
   # Turing portmap off on the server running Oracle, breaks Oracle
   if [ "`hostname -s`" == "$ORACLE_SERVER" ] || [ "`hostname -s`" == "$LH3USER_DATA_AGING_SERVER" ]; then
   	/sbin/chkconfig portmap on
   fi
   /sbin/chkconfig rawdevices off
   /sbin/chkconfig rpcgssd off
   /sbin/chkconfig rpcidmapd off
   /sbin/chkconfig rpcsvcgssd off
   /sbin/chkconfig sendmail off

   #/etc/xinetd.conf perms settings
   chmod 440 /etc/xinetd.conf

   #(FOUO)
   #4.B.3.b(4)(b)
   #Synopsis: Features or procedures for protection of the operating
   #          system from improper changes.
   #
   #KickStart Actions: Actions Listed Below

   #Direct root logins are only allowed via tty1
   if [ -e /etc/securetty.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/securetty /etc/securetty.nolock

   	echo "tty1" > /etc/securetty
   fi

   #Correct the Red Hat supplied modes on these directories
   chmod 750 /var/crash /var/www/usage /usr/libexec/dovecot

   #Change all user files to mode 700
   ######  EDITED DUE TO /HOME BEING ON FILER #########
   #find /home -name '.*' -type f > /tmp/home_permission_change
   find /root -name '.*' -type f > /tmp/root_permission_change
   ######  EDITED DUE TO /HOME BEING ON FILER #########
   #find /home -name '.*' -type f -exec chmod -R 700 {} \;
   find /root -name '.*' -type f -exec chmod -R 700 {} \;

   #Script to create symlinks for dangerous files
   for file in /root/.rhosts /root/.shosts /etc/hosts.equiv
   do
      rm -f $file
      ln -s /dev/null $file
   done 

   #World Writable files
   for part in `awk '($3== "ext2" || $3 == "ext3") \
      { print $2 }' /etc/fstab`
   do
      find $part -xdev -type f -perm -0002 -print > /root/system.ww.txt
   done
   
   #SUID | SGID files
   for part in `awk '($3== "ext2" || $3 == "ext3") \
      { print $2 }' /etc/fstab`
   do
      find $part -xdev -type f -perm -04000 -o -perm -02000 -print > /root/system.suid-sgid.txt
   done

   #Set up tcpwrappers, only ssh traffic is allowed in by default
   if [ -e /etc/hosts.deny.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/hosts.deny /etc/hosts.deny.nolock

   	echo "ALL:ALL" >> /etc/hosts.deny
   fi
   if [ -e /etc/hosts.allow.nolock ] ; then
   	echo "File exists"
   else
     cp -p /etc/hosts.allow /etc/hosts.allow.nolock
     if [ "`hostname -s`" == "$VSFTPD_SERVER" ]; then
       echo "sshd:ALL" >> /etc/hosts.allow
       echo "vsftpd:172.19.*" >> /etc/hosts.allow
     else
       echo "sshd:ALL" >> /etc/hosts.allow
     fi
   fi

   #No one gets to run cron jobs unless we say they can
   if [ -e /etc/cron.allow ]; then
	echo "File exists"
   else
   	touch /etc/cron.allow
   	chmod 600 /etc/cron.allow
   	awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
   fi

   #No one gets to run at jobs unless we say they can
   if [ -e /etc/at.allow ]; then
	echo "File exists"
   else
   	touch /etc/at.allow
   	chmod 600 /etc/at.allow
   	awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny
   fi

   #We need to restrict ssh root logins; meaningless, because root 
   #can only login to tty1
   if [ -e /etc/ssh/sshd_config_prootlog.nolock ]; then
	echo "File exists"
   else
	cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_prootlog.nolock

   	perl -npe 's/#PermitRootLogin yes/PermitRootLogin no/' -i /etc/ssh/sshd_config
   fi

   #Check local device files against baseline
   #as a note, it may be sufficient to do a rpm --verify on the associated 
   #block device packabes (devfs?)
   find /dev -type b -or -type c -or -type s >> /root/blockdevices.`date +%Y:%m:%d644`.txt

   #Reset the umasks for all users to 077
   if [ -e /etc/bashrc.nolock ]; then
	echo "File exists"
   else
	cp -p /etc/bashrc /etc/bashrc.nolock
   	perl -npe 's/umask\s+0\d2/umask 027/g' -i /etc/bashrc
   fi
   if [ -e /etc/profile_umask_all.nolock ]; then
	echo "File exists"
   else
	cp -p /etc/profile /etc/profile_umask_all.nolock
   	perl -npe 's/umask\s+0\d2/umask 027/g' -i /etc/profile
   fi
   if [ -e /etc/csh.cshrc.nolock ]; then
	echo "File exists"
   else
	cp -p /etc/csh.cshrc /etc/csh.cshrc.nolock
   	perl -npe 's/umask\s+0\d2/umask 027/g' -i /etc/csh.cshrc
   fi

   #Correct the perms on /root to a DISA allowed 700
   chmod 700 /root

   #iptable perms settings
   chmod 700 /etc/rc.d/init.d/iptables
   chmod 700 /sbin/iptables
   chmod 700 /usr/share/logwatch/scripts/services/iptables

   #/etc/skel perms settings
   chmod -R 700 /etc/skel

   #/usr/share/man perms settings
   find /usr/share/man -type f -not -perm 644 -exec chmod 644 {} \;

   #/usr/share/doc perms settings
   find /usr/share/doc -type f -exec chmod 644 {} \;

   #/etc/crontab and /etc/log.d/scripts/logwatch.pl perms settings
   chmod 600 /etc/crontab
   chmod 700 /etc/log.d/scripts/logwatch.pl

   #Change all pre-installed system cron jobs to DISA-blessed mode rwx------
   #Some files in here are scripts, though--
   find /etc/cron.*/ -type f -exec chmod 700 {} \;

   #/var/crash perms settings
   chmod 700 /var/crash

   #Sendmail Protection:  Comment out HelpFile flag
   if [ -e /etc/mail/sendmail.cf.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/mail/sendmail.cf /etc/mail/sendmail.cf.nolock

   	perl -npe 's/O\s+HelpFile/#O HelpFile/g' -i /etc/mail/sendmail.cf

   	#Sendmail Protection:  SmtpGreetingMessage string setting
   	perl -npe 's/O\s+SmtpGreetingMessage=.*/O SmtpGreetingMessage=OneDotOneDotOneDotOneDotNunyo-Business/' -i /etc/mail/sendmail.cf
   fi

   #/etc/snmp/snmpd.conf group setting change
   chgrp sys /etc/snmp/snmpd.conf

   #X Settings
   if [ "$RHELVER" = "2.6.9-89.ELsmp" ]; then
   if [ -e /usr/X11R6/bin/startx.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /usr/X11R6/bin/startx /usr/X11R6/bin/startx.nolock
   	perl -npe 's/^defaultserverargs=""/defaultserverargs="-s 15 -audit -auth"/' -i /usr/X11R6/bin/startx
   fi
   fi

   #/etc/sysctl.conf perms settings
   chmod 600 /etc/sysctl.conf

   #Do not allow CTRL ALT DEL command to shutdown the system
   if [ -e /etc/inittab_ctlaltdel.nolock ] ; then
   	echo "File exists"
   else
	cp -p  /etc/inittab /etc/inittab_ctlaltdel.nolock
   	perl -npe 's/ca::ctrlaltdel:\/sbin\/shutdown/#ca::ctrlaltdel:\/sbin\/shutdown/' -i /etc/inittab
   fi

   #/dev/*ty* perms settings
   find /dev -name "*ty*" -exec chmod 700 {} \;
   #changing permissions on /dev/tty to allow ssh
   chmod 666 /dev/tty

   #Delete the following users for protection of the operating system.
   if [ "`hostname -s`" == "$VSFTPD_SERVER" ]; then
     for i in shutdown halt games operator news gopher
     do
       /usr/sbin/userdel $i
     done
   else
     for i in shutdown halt games operator ftp news gopher
     do
       /usr/sbin/userdel $i
     done
   fi

   #Sendmail Vulnerability with the "decode" alias set in /etc/aliases (turn off)
   if [ -e /etc/aliases.nolock ] ; then
   	echo "File exists"
   else
   	cp -p /etc/aliases /etc/aliases.nolock

   	perl -npe 's/^decode/#decode/' -i /etc/aliases
   	newaliases
   fi

   #Change the mode of the maillog file to a DISA-blessed rw-------
   chmod 600 /var/log/maillog

   #/etc/security/access.conf perms settings for DISA
   #Set mode to DISA-blessed rw-r------
   chmod 640 /etc/security/access.conf

   #Need to check on all proper X Server Secuity Settings to Meet DCID 6/3
   #check proper X server options

   #Set the /etc/samba.conf file
   #This will create an attribute so that the /etc/samba/smb.conf file cannot be 
   #modified.  It cannot be deleted or remaned, a link cannot be created to this
   #file, and no data can be written to the the file.
   chattr +i /etc/samba/smb.conf

   #If we're not running an POP/IMAP server, remove the user dovecot
   rpm -q dovecot 2>&1 > /dev/null
   if [ $? = "1" ]
   then
	/usr/sbin/userdel dovecot
   else
	echo "dovecot package installed, not deleting user dovecot"
   fi

   #If we're not running named, delete the user
   rpm -q bind 2>&1 > /dev/null
   if [ $? = "1" ]
   then
        /usr/sbin/userdel named
   else
	echo "bind package installed, not deleting user named"
   fi

#(FOUO)
#4.B.3.b(5) [SysAssur2]
#Synopsis: System Assurance shall include:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(5)(a)
   #Synopsis: Controls of access to the Security Support Structure
   #          (i.e, software hardware, and firmware that perform
   #          operating system or security functions).
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(5)(b)
   #Synopsis: Assurance of the integrity of the Security Support 
   #          Structure.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.b(6) [SysAssur3]
#Synopsis: System Assurance shall include:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(6)(a)
   #Synopsis: Isolating the Security Support Structure by means of
   #          partitions, domains, etc., including control of access
   #          to, and integrity of, hardware, and software and firmware
   #          that perform security functions.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(6)(b)
   #Synopsis: Using up-to-date vulnerability assessment tools to validate
   #          the continued integrity of the Security Support Structure
   #          by ensuring that the system configuration does not contain
   #          any well-known security vulnerabilities.
   #
   #KickStart Actions: None

#(FOUO)
#4.B.3.b(7) [Test2]
#Synopsis: The ISSM shall provide written verification to the DAA that the
#          system operates in accordance with the approved SSP, and that the
#          security features, including access controls, configuration
#          management, and discretionalry access controls, are implemented
#          and operational.
#
#KickStart Actions: None

#(FOUO)
#4.B.3.b(8) [Test3]
#Synopsis: Additional Testing:
#
#KickStart Actions: None

   #(FOUO)
   #4.B.3.b(8)(a)
   #Synopsis: Certification testing shall be conducted including verification
   #          that the features and assurance required for the Protection Level
   #          are functional.
   #
   #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(8)(b)
   #Synopsis: A test plan and procedures shall be developed and include:
   #
   #KickStart Actions: None

      #(FOUO)
      #4.B.3.b(8)(b)(1)
      #Synopsis: A detailed description of the manner in which the system's
      #          Security Support Structure meets the technical requirements
      #          for the Protection Levels and Levels-of-Concern for integrity
      #          and availability.
      #
      #KickStart Actions: None

      #(FOUO)
      #4.B.3.b(8)(b)(2)
      #Synopsis: A detailed description of the assurances that have been implemented
      #          and how this implementation will be verified.
      #
      #KickStart Actions: None

      #(FOUO)
      #4.B.3.b(8)(b)(3)
      #Synopsis: An outline of the inspection and test procedures used to verify this
      #          compliance.
      #
      #KickStart Actions: None

   #(FOUO)
   #4.B.3.b(9) [Test4]
   #Synopsis: Testing, as required by the DAA:
   #
   #KickStart Actions: None

      #(FOUO)
      #4.B.3.b(9)(a)
      #Synopsis: Security Penetration Testing shall be conducted to determine the level 
      #          of difficulty in penetrating the security countermeasures of the 
      #          system.
      #
      #KickStart Actions: None

      #(FOUO)
      #4.B.3.b(9)(b)
      #Synopsis: An Independent Validaton and Verification team shall be formed to 
      #          assist in the security testing and to perform validaton and           
      #          verification testing of the system.
      #
      #KickStart Actions: None

#Give us a way in for testing, otherwise, log in to tty1 as root, and create your own account
#useradd redhat
#echo "red.hat" | passwd --stdin redhat
#usermod -g wheel redhat
#
#
###############################################################################
###############################################################################
#POST INSTALLATION INSTALLS AND CONFIGURATIONS
#echo ""
#echo "Installing RHEL Updates... Please be patient"
#echo ""
#
#
#Change Background and Wallpaper
#   rm -f /usr/share/backgrounds/images/default.png
#   cp -fa /root/DoDIIS/DoDIISsci.png /usr/share/backgrounds/images/default.png
#   rm -f /usr/share/gdm/themes/RHEL/background.png
#   cp -fa /root/DoDIIS/background.png /usr/share/gdm/themes/RHEL/background.png
#
#
#
#Install Bastille and dependent files
#   MY_RPMS=/root/DoDIIS
#   rpm -i $MY_RPMS/jre-1_5_0_11-linux-i586.rpm
#   rpm -i $MY_RPMS/sav-1.0.1-66.i386.rpm
#   rpm -i $MY_RPMS/savap-1.0.1-66.i386.rpm
#   rpm -i $MY_RPMS/savjlu-1.0.1-66.i386.rpm
#   rpm -i $MY_RPMS/savui-1.0.1-66.i386.rpm
#   rpm -i $MY_RPMS/perl-Curses-1.12-1.2.el4.rf.i386.rpm
#   rpm -i $MY_RPMS/perl-Tk-804.027-3.2.el4.rf.i386.rpm
#   rpm -i $MY_RPMS/Bastille-3.0.9-1.0.noarch.rpm
#
#
# Update our RPM's with the lastest updates
#   rpm -F $MY_RPMS/errata/*.rpm
#
#
#
#Run Bastille to lockdown system further
#   LOG=/root/bastille-lockdown.log
#   /bin/touch $LOG
#   cp -f /root/DoDIIS/config-bastille /etc/Bastille/config 2>&1 | tee -a $LOG
#   chown root:root /etc/Bastille/config
#   /usr/sbin/bastille -n -b 2>&1 | tee -a $LOG
#
#
#
#Set permissions on DoDIIS Directory
#   chmod 0700 /root/DoDIIS
#
#
#
#############################################################################
#############################################################################
#GEN001260 (Needs to be at bottom, as it somehow gets reset) --note that the
#culprit doing the reset is /etc/rc.d/rc.sysinit.  I need to find out why
find /var/log/ -type f -not -perm 644 -exec chmod 644 {} \;

#eject
#EOF#
##############################
#END OF KICKSTART FILE POST SETTINGS

#----------------------------------------------------------#

### ARGON TWEAKS ###

#Turn auditd on in run level 1
/sbin/chkconfig --level 1 auditd on

# Send system Halt on disk full or error
if [ -e /etc/audit/auditd.conf.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/audit/auditd.conf /etc/audit/auditd.conf.nolock

	# Synchronously Flush Audit data to disk
	sed s/"flush = INCREMENTAL"/"flush = SYNC"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1

	#Notify on low disk space
	sed s/"space_left_action = SYSLOG"/"space_left_action = email"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1

	#Notify on NO disk space
	sed s/"admin_space_left_action = SUSPEND"/"admin_space_left_action = email"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1

	#Set E-mail Address
	sed s/"action_mail_acct = root"/"action_mail_acct = admin@arc.argoneng.com"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1

	#Set Halt-on-audit failure
	sed s/"disk_full_action = SUSPEND"/"disk_full_action = HALT"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1

	#Set Halt-on-audit errors
	sed s/"disk_error_action = SUSPEND"/"disk_error_action = HALT"/g /etc/audit/auditd.conf > /tmp/tmp1
	cp /tmp/tmp1 /etc/audit/auditd.conf
	rm /tmp/tmp1
fi


#Enable audit in audit.rules
if [ -e /etc/audit/audit.rules.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/audit/audit.rules /etc/audit/audit.rules.nolock

cat <<EOF >> /etc/audit/audit.rules
# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 320

# Feel free to add below this line. See auditctl man page


#Check for the system's response to audit failure.
-f 2

#Ensure that the system is configured to record events that modify the system's date or time. 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

-a always,exit -F arch=b64 -S clock_settime -k time-change

-w /etc/localtime -p wa -k time-change 

#Ensure that the system is configured to record events that modify accounts on the system. 

-w /etc/group -p wa -k identity

-w /etc/passwd -p wa -k identity

-w /etc/gshadow -p wa -k identity

-w /etc/shadow -p wa -k identity

-w /etc/security/opasswd -p wa -k identity 

#Ensure that the system is configured to record events that modify network settings. 

-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale

-w /etc/issue -p wa -k system-locale

-w /etc/issue.net -p wa -k system-locale

-w /etc/hosts -p wa -k system-locale

-w /etc/sysconfig/network -p wa -k system-locale 

#Ensure that the system is configured to record events that modify MAC policy.

-w /etc/selinux/ -p wa -k MAC-policy 

#Ensure that the system is configured to record logon and logout events.
-w /var/log/faillog -p wa -k logins

-w /var/log/lastlog -p wa -k logins

#Ensure that the system is configured to record process and session information. 
-w /var/run/utmp -p wa -k session

-w /var/log/btmp -p wa -k session

-w /var/log/wtmp -p wa -k session 

#Ensure that the system is configured to record file permission changes for all users and root. 

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod 

#Ensure that the system is configured to record unauthorized file accesses. 

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access 

#Ensure that the system is configured to record execution of privileged commands. 
-a always,exit -F path=/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/fusermount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/umount.nfs4 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/mount.nfs -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/mount.nfs4 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/sbin/umount.nfs -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/kerberos/bin/ksu -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/ccreds_validate -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/userisdnctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/sendmail.sendmail -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/lockdev -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/lib/vte/gnome-pty-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/lib/squid/pam_auth -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/lib/squid/ncsa_auth -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/lib/nspluginwrapper/plugin-config -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/rlogin -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/lockfile -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/kgrantpty -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/rsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gataxx -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gnobots2 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gnomine -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/iagno -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gnotravex -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/mahjongg -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gnibbles -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gnotski -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/gtali -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/glines -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/konsole -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/rcp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/Xorg -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/kpac_dhcp_helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/bin/same-gnome -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/lib/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#Ensure that the system is configured to record media exportation events.

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export 

#Ensure that the system is configured to record file deletion events. 

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete 

#Ensure that the system is configured to record system administrator actions. 

-w /etc/sudoers -p wa -k actions 

-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/nspluginwrapper/plugin-config -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/vte/gnome-pty-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#Audit enabled and set as immutable
-e 2

EOF
fi

#Set root umask to 0027
echo "umask 0027" >> /root/.bash_profile

#Fix permissions on root owned files
chmod 0400 /etc/at.allow
chmod 0600 /etc/at.deny
chmod 0600 /etc/audit.rules
chmod 0600 /etc/audit/audit.rules
chmod 0600 /etc/audit/auditd.conf
chmod 0444 /etc/bashrc
chmod 0400 /etc/cron.allow
chmod 0600 /etc/cron.deny
chmod 0400 /etc/crontab
chmod 0444 /etc/csh.cshrc
chmod 0444 /etc/csh.login
chmod 0600 /etc/cups/client.conf
chown lp:sys /etc/cups/client.conf
chmod 0600 /etc/cups/cupsd.conf
chown lp:sys /etc/cups/cupsd.conf
chmod 0444 /etc/hosts
chmod 0600 /etc/inittab
chmod 0640 /etc/login.defs
chmod 0444 /etc/mail/sendmail.cf
chown root:bin /etc/mail/sendmail.cf
chmod 0444 /etc/networks
chmod 0600 /etc/ntp.conf
chmod 0444 /etc/profile
chmod 0644 /etc/resolv.conf
chmod 0744 /etc/rc.d/init.d/auditd
chmod 0600 /etc/rc.d/rc.local
chmod 0600 /etc/rc.local
chmod 0400 /etc/securetty
chmod 0600 /etc/security/console.perms
chmod 0600 /etc/security/console.perms.d/50-default.perms
chmod 0444 /etc/services
chmod 0444 /etc/shells
chmod 0600 /etc/skel/.bashrc
chmod 0600 /etc/rsyslog.conf
chmod 0600 /root/.bash_history
chmod 0600 /root/.bash_logout
chmod 0400 /root/.bash_profile
chmod 0400 /root/.bashrc
chmod 0400 /root/.cshrc
chmod 0400 /root/.tcshrc
chmod 0600 /var/log/btmp
chmod 0600 /var/log/dmesg
chmod 0600 /var/log/faillog
chmod 0400 /var/log/lastlog
chmod 0600 /var/log/messages
chmod 0600 /var/log/scrollkeeper.log
chmod 0600 /var/log/secure
chmod 0600 /var/log/wtmp

#Change permissions on critical directories
chmod 0750 /etc/cron.d
chmod 0750 /etc/cron.daily
chmod 0750 /etc/cron.hourly
chmod 0750 /etc/cron.monthly
chmod 0750 /etc/cron.weekly
chmod 0750 /etc/security
chmod 0750 /root/.ssh/
chmod 0644 /usr/share/doc
chmod 0644 /usr/share/man

#Change permissions on world writeable directories
chmod 775 /var/cache/coolkey
chmod 775 /var/spool/vbox
chmod 775 /var/tmp
chmod 775 /home
chmod 775 /tmp/.font-unix
chmod 775 /tmp/.ICE-unix
chmod 775 /dev/shm

#Remove SUID 
chmod 0711 /usr/sbin/userhelper
chmod 0755 /usr/sbin/userisdnctl
chmod 0755 /usr/kerberos/bin/ksu
chmod 0755 /usr/bin/rlogin
chmod 0755 /usr/bin/rcp
chmod 0755 /usr/bin/rsh
chmod 0755 /bin/ping6
chmod 0755 /usr/sbin/usernetctl
chmod 0755 /usr/libexec/openssh/ssh-keysign
chmod 0711 /usr/bin/chfn
chmod 0555 /usr/bin/wall
chmod 0755 /usr/bin/write

#Remove SETGID
chmod 0755 /sbin/netreport

#Set user /home directories to 750
for dir in `ls /home`
do
chmod 750 /home/$dir
done


#Shutdown services
/sbin/chkconfig autofs off
/sbin/chkconfig firstboot off
/sbin/chkconfig hplip off
/sbin/chkconfig isdn off
/sbin/chkconfig mcstrans off
/sbin/chkconfig mdmonitor off
/sbin/chkconfig setroubleshoot off
/sbin/chkconfig yum-updatesd off

#Touch /etc/ftpusers
if [ -e /etc/ftpusers.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/ftpusers /etc/ftpusers.nolock
cat <<EOF >> /etc/ftpusers
bin
sabayon
mailnull
nobody
lp
rpm
gdm
nscd
root
mail
daemon
ntp
uucp
rpc
sync
haldaemon
smmsp
adm
dbus
rpcuser
pcap
xfs
vcsa
avahi
sshd
EOF

chmod 0600 /etc/ftpusers
fi

#Touch /etc/vsftp/ftpusers
if [ -e /etc/vsftpd/ftpusers.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/vsftpd/ftpusers /etc/vsftpd/ftpusers.nolock
cat <<EOF >> /etc/vsftpd/ftpusers
bin
sabayon
mailnull
nobody
lp
rpm
gdm
nscd
root
mail
daemon
ntp
uucp
rpc
sync
haldaemon
smmsp
adm
dbus
rpcuser
pcap
xfs
vcsa
avahi
sshd
EOF

chmod 0600 /etc/vsftpd/ftpusers
fi

#Lock down sshd_config
if [ -e /etc/ssh/sshd_config_strict.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_strict.nolock
cat <<EOF >> /etc/ssh/sshd_config

MaxAuthTries 1
IgnoreRhosts yes
PermitEmptyPasswords no
LogLevel info
HostbasedAuthentication no
GatewayPorts no
PrintLastLog yes
PermitUserEnvironment no
X11Forwarding no

EOF
fi

#Restrict root logins to local console
if [ -e /etc/securetty_root_console.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/securetty /etc/securetty_root_console.nolock

	echo "console" >> /etc/securetty
fi

#Don't accept ipv4 redirects
if [ -e /etc/sysctl_ipv4.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/sysctl.conf /etc/sysctl_ipv4.nolock
	
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

#Add MOTD Banner
if [ -e /etc/motd.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/motd /etc/motd.nolock
echo "NOTICE AND CONSENT BANNER

This is a Department of Defense (DoD) Computer System. This computer system, including all related equipment, networks, and network devices (specifically including Internet access), are provided only for authorized U.S. government use. DoD computer systems may be monitored for all lawful purposes, including to ensure that their use is authorized, for management of the system, to facilitate protection against unauthorized access, and to verify security procedures, survivability and operational security.

Monitoring includes active attacks by authorized DoD entities to test or verify the security of this system. During monitoring, information may be examined, recorded, copied, and used for authorized purposes. All information, including personal information, placed on or sent over this system may be monitored. Use of this DoD computer system, authorized or unauthorized, constitutes consent to monitoring of this system. Unauthorized use may subject you to criminal prosecution. Evidence of unauthorized use collected during monitoring may be used for administrative, criminal, or other adverse action. Use of this system constitutes consent to monitoring for these purposes." >> /etc/motd
fi

#Add /etc/issue Banner
if [ -e /etc/issue.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/issue /etc/issue.nolock
echo "NOTICE AND CONSENT BANNER

This is a Department of Defense (DoD) Computer System. This computer system, including all related equipment, networks, and network devices (specifically including Internet access), are provided only for authorized U.S. government use. DoD computer systems may be monitored for all lawful purposes, including to ensure that their use is authorized, for management of the system, to facilitate protection against unauthorized access, and to verify security procedures, survivability and operational security.

Monitoring includes active attacks by authorized DoD entities to test or verify the security of this system. During monitoring, information may be examined, recorded, copied, and used for authorized purposes. All information, including personal information, placed on or sent over this system may be monitored. Use of this DoD computer system, authorized or unauthorized, constitutes consent to monitoring of this system. Unauthorized use may subject you to criminal prosecution. Evidence of unauthorized use collected during monitoring may be used for administrative, criminal, or other adverse action. Use of this system constitutes consent to monitoring for these purposes." >> /etc/issue
fi

#Add /etc/issue.net Banner
if [ -e /etc/issue.net.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/issue.net /etc/issue.net.nolock
echo "NOTICE AND CONSENT BANNER

This is a Department of Defense (DoD) Computer System. This computer system, including all related equipment, networks, and network devices (specifically including Internet access), are provided only for authorized U.S. government use. DoD computer systems may be monitored for all lawful purposes, including to ensure that their use is authorized, for management of the system, to facilitate protection against unauthorized access, and to verify security procedures, survivability and operational security.

Monitoring includes active attacks by authorized DoD entities to test or verify the security of this system. During monitoring, information may be examined, recorded, copied, and used for authorized purposes. All information, including personal information, placed on or sent over this system may be monitored. Use of this DoD computer system, authorized or unauthorized, constitutes consent to monitoring of this system. Unauthorized use may subject you to criminal prosecution. Evidence of unauthorized use collected during monitoring may be used for administrative, criminal, or other adverse action. Use of this system constitutes consent to monitoring for these purposes." >> /etc/issue.net
fi

#Add /etc/gdm/custom.conf Banner
if [ -e /etc/gdm/custom.conf.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/gdm/custom.conf /etc/gdm/custom.conf.nolock
cat <<EOF >> /etc/gdm/custom.conf

Greeter=NOTICE AND CONSENT BANNER. THIS IS A DEPARTMENT OF DEFENSE (DOD) COMPUTER SYSTEM. THIS COMPUTER SYSTEM, INCLUDING ALL RELATED EQUIPMENT, NETWORKS AND NETWORK DEVICES (SPECIFICALLY INCLUDING INTERNET ACCESS), ARE PROVIDED ONLY FOR AUTHORIZED U.S. GOVERNMENT USE. DOD COMPUTER SYSTEMS MAY BE MONITORED FOR ALL LAWFUL PURPOSES, INCLUDING TO ENSURE THAT THEIR USE IS AUTHORIZED, FOR MANAGEMENT OF THE SYSTEM, TO FACILITATE PROTECTION AGAINST UNAUTHORIZED ACCESS, AND TO VERIFY SECURITY PROCEDURES, SURVIVABILITY, AND OPERATIONAL SECURITY. MONITORING INCLUDES ACTIVE ATTACKS BY AUTHORIZED DOD ENTITIES TO TEST OR VERIFY THE SECURITY OF THIS SYSTEM. DURING MONITORING INFORMATION MAY BE EXAMINED, RECORDED, COPIED, AND USED FOR AUTHORIZED PURPOSES. ALL INFORMATION, INCLUDING PERSONAL INFORMATION, PLACED ON OR SENT OVER THIS SYSTEM MAY BE MONITORED. USE OF THIS DOD COMPUTER SYSTEM, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO MONITORING OF THIS SYSTEM. UNAUTHORIZED USE MAY SUBJECT YOU TO CRIMINAL PROSECUTION. EVIDENCE OF UNAUTHORIZED USE COLLECTED DURING MONITORING MAY BE USED FOR ADMINISTRATIVE, CRIMINAL OR OTHER ADVERSE ACTION. USE OF THIS SYSTEM CONSTITUTES CONSENT TO MONITORING FOR THESE PURPOSES.

DisallowTCP=true

EOF
fi

if [ -e /boot/grub/grub.conf.nolock ] ; then
	echo "File exists"
else
        cp -p /boot/grub/grub.conf /boot/grub/grub.conf.nolock
	sed -i -e "/.*kernel.*rhgb.*quiet.*/s/\$/ audit=1/" /boot/grub/grub.conf
	chmod 600 /etc/grub.conf
fi

if [ -d /opt/hyperic ]; then
	chmod 0775 /opt/hyperic/hyperic-3.2.2-ee/hq-plugins
	chmod 0775 /opt/hyperic/hyperic-3.2.2-ee/server-3.2.2-EE/hq-engine/server/default/deploy/hq.ear/hq-plugins
	chmod 0775 /opt/hyperic/hyperic-3.2.2-ee/server-3.2.2-EE/hq-engine/server/default/deploy/hq.ear/hq.war/hqu
fi

chmod 0775 /usr/bin/chage

#Change default umask
if [ -e /etc/init.d/functions.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/init.d/functions /etc/init.d/functions.nolock

	sed s/"umask 022"/"umask 027"/g /etc/init.d/functions > /tmp/tmp1
	cp /tmp/tmp1 /etc/init.d/functions
	rm /tmp/tmp1
fi
if [ -e /etc/profile.umask.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/profile /etc/profile.umask.nolock

	echo "umask 027" >> /etc/profile
fi

#Set prompt to no
if [ -e /etc/sysconfig/init.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/sysconfig/init /etc/sysconfig/init.nolock

	sed s/"PROMPT=yes"/"PROMPT=no"/g /etc/sysconfig/init > /tmp/tmp1
	cp /tmp/tmp1 /etc/sysconfig/init
	rm /tmp/tmp1
fi

#Turn of X by default
if [ -e /etc/inittab.r3.nolock ] ; then
	echo "File exists"
else
        cp -p /etc/inittab /etc/inittab.r3.nolock

	sed s/"id:5:initdefault:"/"id:3:initdefault:"/g /etc/inittab > /tmp/tmp1
	cp /tmp/tmp1 /etc/inittab
	rm /tmp/tmp1
fi

#Remove shell from /etc/passwd on non-login accounts
if [ -e /etc/passwd.rm_shell.nolock ] ; then
        echo "File exists"
else
        cp -p /etc/passwd /etc/passwd.rm_shell.nolock

	sed s/"\/bin\/sync"/"\/sbin\/nologin"/g /etc/passwd > /tmp/tmp1
	cp /tmp/tmp1 /etc/passwd
	rm /tmp/tmp1

	sed s/"\/sbin\/halt"/"\/sbin\/nologin"/g /etc/passwd > /tmp/tmp1
	cp /tmp/tmp1 /etc/passwd
	rm /tmp/tmp1

	sed s/"\/sbin\/shutdown"/"\/sbin\/nologin"/g /etc/passwd > /tmp/tmp1
	cp /tmp/tmp1 /etc/passwd
	rm /tmp/tmp1

	sed s/"\/etc\/news:"/"\/etc\/news:\/sbin\/nologin"/g /etc/passwd > /tmp/tmp1
	cp /tmp/tmp1 /etc/passwd
	rm /tmp/tmp1
fi

if [ -e /etc/sysconfig/syslog.nolock ] ; then
        echo "File exists"
else
        cp -p /etc/sysconfig/syslog /etc/sysconfig/syslog.nolock

	sed s/"-r -m 0"/"-m 0"/g /etc/sysconfig/syslog > /tmp/tmp1
	cp /tmp/tmp1 /etc/sysconfig/syslog
	rm /tmp/tmp1
fi

rm /var/log/audit/audit.*

sysctl -p
