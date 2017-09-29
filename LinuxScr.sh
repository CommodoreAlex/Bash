#!/bin/bash

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
          	ufw allow 3306 #Mysql
          else
          	echo "Could not enable UFW."
          fi
  fi
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

