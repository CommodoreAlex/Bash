#!/bin/bash

### The user must be logged in as root when running this script. ###

if [ $EUID != 0 ]; then
	echo "[!] You are not root."
	exit
fi

firewall(){

	# Aptitude is used to meet the goals of the operation - in the second if statement
  	# choose what ports you want to allow prior to running this section of the script
  	apt-get install aptitude -y /dev/null
  	if aptitude show ufw | grep -q "State: not installed"; then
        	apt-get install ufw -y
        	if ufw status | grep -q "Status: inactive"; then
          		ufw default deny
          		ufw enable
          		#ufw allow 22 #SSH
          		#ufw allow 25 #SMTP
          		#ufw allow 110 #POP3
          		#ufw allow 139 #Samba
          		#ufw allow 445 #Samba
          		#ufw allow 137 #Samba
          		#ufw allow 138 #Samba
          		#ufw allow 3306 #Mysql
          	else
          		echo "Could not enable UFW."
          	fi
  	fi
	
  	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
        iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
        iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
        iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
        iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
        iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
        iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
        iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
        iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
        iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.
}

sys(){

  if grep -Fxq "STEM SCRIPT HAS BEEN RUN IN THIS FILE." /etc/sysctl.conf; then
	  echo "" &> /dev/null
  else
	  #SYSCTL SETTINGS:
	  #Navigate to $ nano /etc/sysctl.conf
	  #Edit the file and uncomment or add the following lines…
	  echo "STEM SCRIPT HAS BEEN RUN IN THIS FILE." >> /etc/sysctl.conf
	  # IP Spoofing protection
	  echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
	  echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
	  # Ignore ICMP broadcast requests
	  echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
	  # Disable source packet routing
	  echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
	  echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
	  echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
	  echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
	  # Ignore send redirects
	  echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	  echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
	  # Block SYN attacks
	  echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	  echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
	  echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
	  echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
	  # Log Martians
	  echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
	  echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
	  # Ignore ICMP redirects
	  echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	  echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	  echo "net.ipv4.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
	  echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	  # Ignore Directed pings
	  echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
	  #Then reload sysctl with the latest changes…
	  sysctl -p
	  # Disable IPv6 on Ubuntu all-together
	  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
	  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
	  echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
	  sysctl -p
  fi
}

ssh(){
	
	### Enables and creates a MOTD Banner message ###
	if grep -Fxq "#Banner /etc/issue.net" /etc/ssh/sshd_config; then
        	sed -i 's/#Banner/etc/issue.net/Banner /etc/issue.net' /etc/ssh/sshd_config &> /dev/null
		echo "All connections are monitored and recorded" >> /etc/issue.net &> /dev/null
		echo "Disconnect IMMEDIATELY if you are not an authorized user!" >> /etc/issue.net &> /dev/null
   	fi
	### Enables IgnoreRhosts ###
	if grep -Fxq "IgnoreRhosts no" /etc/ssh/sshd_config; then
    		sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config &> /dev/null
 	fi
	### Enables UsePAM ###
	if grep -Fxq "UsePAM no" /etc/ssh/sshd_config; then
		sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config &> /dev/null
	fi
	### Enables PrintMotd ###
	if grep -Fxq "PrintMotd no" /etc/ssh/sshd_config; then
		sed -i 's/PrintMotd no/PrintMotd yes/g' /etc/ssh/sshd_config &> /dev/null
	fi
	### Enables UsePrivilegeSeparation ###
	if grep -Fxq "UsePrivilegeSeparation no" /etc/ssh/sshd_config; then
    		sed -i 's/UsePrivilegeSeparation no/UsePrivilegeSeparation yes/g' /etc/ssh/sshd_config &> /dev/null
  	fi
	### Permits root login from 'YES' to 'NO' ###
	if grep -Fxq "PermitRootLogin yes" /etc/ssh/sshd_config; then
		sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config &> /dev/null
	fi
	### PermitRootLogin without password to no ###
 	if grep -Fxq "PermitRootLogin without-password" /etc/ssh/sshd_config; then
    		sed -i 's/PermitRootLogin without-password/PermitRootLogin no/g' /etc/ssh/sshd_config &> /dev/null
  	fi
	### Changes X11Forwarding from 'YES' to 'NO' ###
	if grep -Fxq "X11Forwarding yes" /etc/ssh/sshd_config; then
		sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config &> /dev/null 
	fi
	### Permits empty passwords from 'YES' to 'NO' ###
	if grep -Fxq "PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
		sed -i 's/PermitEmptyPasswords yes/PermitEmpyPasswords no/g' /etc/ssh/sshd_config &> /dev/null
	fi
	### Changes protocol 1 to 2 ###
	if grep -Fxq "Protocol 1" /etc/ssh/sshd_config; then
	  sed -i 's/Protocol 1/Protocol 2/g' /etc/ssh/sshd_config &> /dev/null
	fi
  
	service ssh reload
	clear
}

pam(){

	apt-get install libpam-cracklib -y
	apt-get install auditd -y
	auditctl -e 1

	### Common-password ### 

	if grep -Fxq "password        requisite                       pam_cracklib.so" /etc/pam.d/common-password; then
        	sed -i 's/password        requisite                       pam_cracklib.so/password        requisite                       pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrep$
	fi
	if grep -Fxq "password        requisite                       pam_pwhistory.so" /etc/pam.d/common-password; then
        	sed -i 's/password        requisite                       pam_pwhistory.so/password        requisite                       pam_pwhistory.so use_authtok remember=24 enforce_for_root/g' /etc/pam.d/c$
	fi
	### Common-auth ###
	if grep -Fxq "auth    optional                        pam_cap.so" /etc/pam.d/common-auth; then
        	sed -i 's/auth    optional                        pam_cap.so/auth    optional                        pam_cap.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent/g' /etc/pam.d/$
	fi
	### /etc/login.defs ### 
	sed -i 's/PASS_MAX_DAYS 99999/PASS_MAX_DAYS 30/g' /etc/login.defs
	sed -i 's/PASS_MIN_DAYS 0/PASS_MIN_DAYS 8/g' /etc/login.defs
	sed -i 's/PASS_WARN_AGE 0/PASS_WARN_AGE 7/g' /etc/login.defs
	echo "PASS_MIN_LEN 8" >> /etc/login.defs
}

guest(){

	### Guest Account 16.04 ###
	if lsb_release -a | grep -q "Release:   16.04"; then
        	mkdir /etc/lightdm/lightdm.conf.d/
		echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/50-no-guest.conf
        	echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf.d/50-no-guest.conf
		echo "RUNS"
	fi

	### Guest Account 14.04 ###
	if lsb_release -a | grep -q "Release:	14.04"; then
		### Disable guest account ###
		if grep -q "allow-guest=true" /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf; then
			echo "Changing allow-guest=true/allow-guest=false."
			sed -i 's/allow-guest=true/allow-guest=false/g' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		else
			echo "allow-guest=false" >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		fi
	fi
	### Hide user at logon ###
	if grep -q "greeter-hide-users=false" /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf; then
		echo "Chaning users=false/users=true"
		sed -i 's/greeter-hide-users=false/greeter-hide-users=true/g' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	else
		echo "greeter-hide-users=true" >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	fi
	echo "RUNS"

	### Guest Account 12.04 ###
	if lsb_release -a | grep -q "Release:   12.04"; then
		### Disable guest account ###
		if grep -q "allow-guest=true" /etc/lightdm/lightdm.conf; then
			echo "Changing allow-guest=true/allow-guest=false"
			sed -i 's/allow-guest=true/allow-guest=false/g' /etc/lightdm/lightdm.conf
		else
			echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
		fi
	fi
	### Hide user at logon ###
	if grep -q "greeter-hide-users=false" /etc/lightdm/lightdm.conf; then
		sed -i 's/greeter-hide-users=false/greeter-hide-users=true/g' /etc/lightdm/lightdm.conf
        else
                echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf
        fi
	echo "RUNS"
}






