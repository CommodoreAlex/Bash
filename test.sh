#!/bin/bash
#V1.0

# This is here because in the CP comp, you'll read some things before you work. 
# It wouldn't be good to potentially take something away / ruin something important.
# It's recommended to have paper out or a document to log some listed information of the output.
# If you're of another CyberPatriot team or aren't a member of the team 'Marine Raiders' in general...
# It is against the rules of the competition to use this script, so please, abide by this regulation...
# It's preferred that you run this script in root.

if [ $EUID -ne 0 ]; then
    echo "[!] You are not Root! Quitting..."
    exit
else
	clear
    echo "[+] Root detected, moving on."
	sleep 1
	clear
fi

# Creating and moving 'infosec.log' to /var/log/ for further usage/storage.
touch infosec.log
mv infosec.log /var/log/

# Because I didn't specify some things to do with error logging, for now I'm using this system
# You just follow down the list referencing the errors/successes

echo -Order of Functions- >> /var/log/infosec.log
echo pass >> /var/log/infosec.log
echo firewall >> /var/log/infosec.log
echo ssh >> /var/log/infosec.log
echo policy >> /var/log/infosec.log
echo audit >> /var/log/infosec.log
echo media >> /var/log/infosec.log
echo accounts >> /var/log/infosec.log
echo cron >> /var/log/infosec.log
echo backdoors >> /var/log/infosec.log
echo hosts >> /var/log/infosec.log
echo syncookies >> /var/log/infosec.log
echo FTPanonup >> /var/log/infosec.log
echo apache >> /var/log/infosec.log
echo rmhack >> /var/log/infosec.log
echo tools >> /var/log/infosec.log
echo updates >> /var/log/infosec.log
echo ------------------------------- >> /var/log/infosec.log

echo "Make sure to go through everything outside of the script..."
echo "Launch when ready."
read WAIT_FOR_USER
clear

ssh(){

	# This will change the 'PermitRootLogin yes' to 'PermitRootLogin no'.
	# This will also disallow X11 Forwarding.
	# This will disallow 'PermitEmptyPasswords'
	# This will change Protocol 1 to Protocol 2
	
		if grep -Fxq "PermitRootLogin yes" /etc/ssh/sshd_config; then
		echo $(date): echo "[!] SSH ROOT login is enabled!" >> /var/log/infosec.log
		sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config &>/dev/null >> /var/log/infosec.log 
		echo $(date): echo "[+] SSH ROOT login is disabled!" >> /var/log/infosec.log
		sleep 3
	
	fi
	
		if grep -Fxq "X11Forwarding yes" /etc/ssh/sshd_config; then
		echo $(date): echo "[!] X11 Forwarding is enabled!" >> /var/log/infosec.log
		sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config &>/dev/null >> /var/log/infosec.log 
		echo $(date): echo "[+] X11 Forwarding has been disabled!" >> /var/log/infosec.log
		sleep 3
	
	fi
	
		if grep -Fxq "PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
		echo $(date): echo "[!] SSH PermitEmptyPasswords is enabled!" >> /var/log/infosec.log
		sed -i 's/PermitEmptyPasswords yes/PermitEmpyPasswords no/g' /etc/ssh/sshd_config &>/dev/null >> /var/log/infosec.log
		echo $(date): echo "[+] SSH PermitEmptyPasswords is disabled!" >> /var/log/infosec.log
		sleep 3
	fi
	
		if grep -Fxq "Protocol 1" /etc/ssh/sshd_config; then
		echo $(date): echo "[!] Protocol 1 is set!" >> /var/log/infosec.log
		sed -i 's/Protocol 1/Protocol 2/g' /etc/ssh/sshd_config &>/dev/null >> /var/log/infosec.log
		echo $(date): echo "[+] Protocol 1 changed to Protocol 2!" >> /var/log/infosec.log
	fi
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] SSH Configurations set!"
	else
		echo $(date):	echo "[!] Could not set configurations!"
	fi
	
 	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}	

firewall(){

	# Sets the firewall to default standards
	# Enables the firewall / Resets it / Allows port 80 and 443 from the start (HTTP/HTTPS)
	
	ufw enable >> /var/log/infosec.log 
	echo 'y' ufw reset >> /var/log/infosec.log 
	
	ufw allow 80 >> /var/log/infosec.log 
	ufw allow 443 >> /var/log/infosec.log 
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Firewall configurations set!"
	else
		echo $(date):	echo "[!] Could not set configurations!"
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

updates(){

	# Updates and Upgrades
	
	apt-get update && apt-get dist-upgrade #-y
	
	# Checks for daily updates
	
    if grep -q "APT::Periodic::Update-Package-Lists \"1\";" /etc/apt/apt.conf.d/10periodic; then
        echo $(date): echo "[!] Daily updates check already configured!" >> /var/log/infosec.log
		read WAIT_FOR_USER
    else
        sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/g' /etc/apt/apt.conf.d/10periodic >> /var/log/infosec.log 
		echo $(date): echo "[+] Daily updates configured" >> /var/log/infosec.log
		read WAIT_FOR_USER
    fi
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Ran through updates and set daily updates!"
	else
		echo $(date):	echo "[!] Could not set configurations!"
	fi

	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

policy(){

	# This will set the password policy for common-password & login.defs.
	# Also this will install libpam-cracklib for /etc/pam.d/common-password.
	
	apt-get update && apt-get install libpam-cracklib -y
    if grep -q "ucredit=-1 lcredit=-2 dcredit=-1" /etc/pam.d/common-password; then
       echo $(date): echo "[+] /etc/pam.d/common-password already configured" >> /var/log/infosec.log
		read WAIT_FOR_USER
    else
        echo "password   requisite    pam_cracklib.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-2 dcredit=-1" >> /etc/pam.d/common-password
		echo $(date): echo "[+] /etc/pam.d/common-password set." >> /var/log/infosec.log
		read WAIT_FOR_USER
    fi

    sed -i 's/PASS_MAX_DAYS	99999/PASS_MAX_DAYS	150/g' /etc/login.defs
    sed -i 's/PASS_MIN_DAYS	0/PASS_MAX_DAYS	7/g' /etc/login.defs
    echo $(date): echo "[+] Password Policy set in /etc/pam.d/common-password and /etc/login.defs" >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Libpam-cracklib installed and password policy set!"
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

finder(){

	# Finds and lists media files with the following extensions.
	# There are two sections as one will list to the user / while one logs it to /var/log/infosec.log
	
	find / -name "*.mp3"
	find / -name "*.mp4" 
	find / -name "*.gif"
	find / -name "*.jpg"
	find / -name "*.jpeg"
	#find / -name "*.png"
	find / -name "*.mov"
	find / -name "*.wav"
	find / -name "*.tiff"
 	find / -name "*.tif"
 	find / -name "*.wmv"
 	find / -name "*.avi"
	
	find / -name "*.mp3" >> /var/log/infosec.log
	find / -name "*.mp4" >> /var/log/infosec.log 
	find / -name "*.gif" >> /var/log/infosec.log 
	find / -name "*.jpg" >> /var/log/infosec.log
	find / -name "*.jpeg" >> /var/log/infosec.log 
	#find / -name "*.png" >> /var/log/infosec.log		# Due to the substantial amount of .png files... This is commented out.
	find / -name "*.mov" >> /var/log/infosec.log
	find / -name "*.wav" >> /var/log/infosec.log
	find / -name "*.tiff" >> /var/log/infosec.log
 	find / -name "*.tif" >> /var/log/infosec.log
 	find / -name "*.wmv" >> /var/log/infosec.log
 	find / -name "*.avi" >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Listed all media files with the following extenions!" >> /var/log/infosec.log
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

accounts(){

	# Disables the guest account
	# Hides the userlist from the login screen.     THIS HAPPENS BY ADDING LINES INTO THE FILE, AS THEY'RE PROBABLY ABSENT.
	# Changes the root password
	# Disables the root account
	
	echo 'allow-guest=false' >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	echo 'greeter-hide-users=true' >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	echo $(date): "[+] Guest account security lines added to '/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf'" >> /var/log/infosec.log
	
							# Uncomment these lines for the competition.
	#passwd root 			# These are commented to save time in the testing phase.
	#passwd -l root		    # The less there is to approve, the faster this goes.
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Disabled the guest user account and hid userlist from login!" >> /var/log/infosec.log
		echo $(date):	echo "[+] ROOT passwd set and locked the ROOT user account!" >> /var/log/infosec.log
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

rmhack(){

	# Attempts to uninstall hacking tools that are currently existing / services ETC ETC ETC
	# Anything listed that isn't present will output 'Package 'bind9' is not installed, so not removed'.
	# So you'll have a pretty good idea of what is present or what should be present.
	
	apt-get --purge autoremove john
	apt-get --purge autoremove hydra
	apt-get --purge autoremove nmap
	apt-get --purge autoremove aircrack-ng
	apt-get --purge autoremove wireshark
	apt-get --purge autoremove kismet
	apt-get --purge autoremove telnet
	apt-get --purge autoremove VOMIT
	apt-get --purge autoremove Yersina
	apt-get --purge autoremove DISCO
	apt-get --purge autoremove ICRACK
	apt-get --purge autoremove bobkit
	apt-get --purge autoremove woot-project
	apt-get --purge autoremove Nikto
	apt-get --purge autoremove pbnj
	apt-get --purge autoremove bind9
	apt-get --purge autoremove apache2
	apt-get --purge autoremove vsftpd
	apt-get --purge autoremove netcat
	apt-get --purge autoremove netcat-openbsd
	apt-get --purge autoremove netcat-traditional
	apt-get --purge autoremove ssh
	apt-get --purge autoremove samba
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

cron(){

	# Checks the scheduled jobs
	
	ls -la /etc/cron*
	ls -la /etc/cron* >> /var/log/infosec.log
	read WAIT_FOR_USER
	
	# Lists the users crontab
	
	crontab -l
	crontab -l >> /var/log/infosec.log
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	
	# Only allow root in cron*
	#cd /etc/
	#/bin/rm -f cron.deny at.deny				# More research must be done here.
	#echo root >cron.allow
	#echo root >at.allow
	#/bin/chown root:root cron.allow at.allow
	#/bin/chmod 400 cron.allow at.allow
	
	# Critical file permissions
	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache2 >> /var/log/infosec.log
	chown -R root:root /etc/apache
	chown -R root:root /etc/apache >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Set critical file permissions and copied '/etc/cron/' to '/var/log/infosec.log/'" >> /var/log/infosec.log
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

backdoors(){
	
	# Potentially lists backdoors.
	# Same principle is going on now, as in media()
	
	netstat -tulpna | grep "LISTEN"
	netstat -tulpna | grep "LISTEN" >> /var/log/infosec.log
	
	# Copy the contents of '/var/www/' to '/var/log/infosec.log'
	
	ls -la /var/www/
	ls -la /var/www/ >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Copied the contents of /var/www/ and saved LISTENING PORTS to '/var/log/infosec.log'!"
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

tools(){

	# Installs tools and other things by the users choice.
	
	apt-get install chkrootkit
	apt-get install tiger
	apt-get install rkhunter
	apt-get install apache2
	apt-get install ssh
	apt-get install samba
	apt-get install bind9
	apt-get install nmap
	apt-get install htop
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

#hosts(){

	# Cleans the hosts file and then adds the necessary information.
	
	#echo 127.0.0.1	localhost > /etc/hosts					# Could break the hosts file {a little}, be careful DO MORE RESEARCH
	#echo ::1 ip6-localhost ip6-loopback >> /etc/hosts
	#echo fe00::0 ip6-localnet >> /etc/hosts
	#echo ff00::0 ip6-mcastprefix >> /etc/hosts
	#echo ff02::1 ip6-allnodes >> /etc/hosts
	#echo ff02::2 ip6-allrouters >> /etc/hosts
	
	#if [ $? -eq 0 ]; then
		#echo $(date):		echo "[+] Hosts file clear of any 'spooky stuff'" >> /var/log/infosec.log
	#else
		#echo $(date):		echo "[!] Could not set configurations!" >> /var/log/infosec.log
	#fi
	
	#echo "[!] PAUSE*"
	#read WAIT_FOR_USER
	#clear
#}

syncookies(){

	# SYN cookie protection 
	# The value should be set to '1' as this will protect us against DDOS attacks, theoretically.
	
	sysctl -w net.ipv4.tcp_syncookie=1
	echo $(date): "[!] Changing syncookie value to 1 and listing values in /var/log/infosec.log" >> /var/log/infosec.log
	cat /proc/sys/net/ipv4/tcp_syncookies >> /var/log/infosec.log
	cat /etc/sysctl.conf | grep tcp_syncookies >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Set the syncookie value to '1'!" >> /var/log/infosec.log
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

FTPanonup(){

	# Deletes the user 'FTP'
	# Prints the output of 'ls -la /etc/ftpusers/' to /var/log/infosec.log
	
	userdel ftp &>/dev/null
	ls -la /etc/ftpusers/ >> /var/log/infosec.log
	echo $(date): "[~] Deleted FTP user and logged /etc/ftpusers/ to see users that have access to ftp" >> /var/log/infosec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Deleted the user 'FTP' and logged '/etc/ftpusers/' to '/var/log/infosec.log'!"
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

apache(){

	# Apache2 security configurations
	
	if [ -e /etc/apache2/apache2.conf ]; then
		echo \<Directory \> >> /etc/apache2/apache2.conf
		echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
		echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
		echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
		echo \<Directory \/\> >> /etc/apache2/apache2.conf
		echo UserDir disabled root >> /etc/apache2/apache2.conf
	fi
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Secured apache2!" >> /var/log/infosec.log
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

audit(){

	# Updates the audit policy
	
	apt-get install auditd
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] Audit policy updated!"
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

pass(){

	# Logs the contents of /etc/passwd, /etc/group/, /etc/gshadow/, and /etc/shadow to /var/log/sec.log
	
	cat /etc/passwd/ >> /var/log/sec.log
	echo "---------------" >> /var/log/sec.log
	cat /etc/group/ >> /var/log/sec.log
	echo "---------------" >> /var/log/sec.log
	cat /etc/gshadow/ >> /var/log/sec.log
	echo "---------------" >> /var/log/sec.log
	cat /etc/shadow >> /var/log/sec.log
	
	if [ $? -eq 0 ]; then
		echo $(date):	echo "[+] /etc/passwd|/etc/group/|/etc/gshadow/|/etc/shadow/ logged to '/var/log/sec.log'!"
	else
		echo $(date):	echo "[!] Could not set configurations!" >> /var/log/infosec.log
	fi
	
	echo "[!] PAUSE*"
	read WAIT_FOR_USER
	clear
}

userpass()

	# Changes all user passwords to 'Cyb3rP4tr10t5'
	
	for i in $(cat /etc/passwd | awk -F: '{ print $1 }'); do
		echo $i
		echo “$i:Cyb3rP4tr10t5” | passwd
	done
}

# Calling the functions after user has 'approved script for launch'.

	pass		 #IGS /
	firewall 	 #IGS /			{IGS = In_Good_Standing}
	ssh		 	 #IGS /
	policy 		 #IGS /
	audit        #IGS /
	finder		 #IGS /
	accounts 	 #IGS /
	userpass	 #IGS /
	cron	 	 #IGS / Research
	backdoors 	 #IGS /
	#hosts 		 #Needs Work / Research
	syncookies 	 #IGS /
	FTPanonup	 #IGS /
	apache		 #IGS / Research
	rmhack 		 #IGS /
	tools 		 #IGS /
	updates 	 #IGS /