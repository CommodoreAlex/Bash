# Technical Portfolio - Bash Projects

Welcome to my technical portfolio for Bash projects. This repository features a collection of Bash scripts designed for automation, security tasks, and system administration. Each script is created to address specific use cases and demonstrates my expertise in shell scripting and system operations.
## Projects and Files Overview

### **CTF & Penetration Testing Tools**


**CTFGEN.sh**  
* Automates reconnaissance tasks commonly used in Capture The Flag (CTF) challenges. The script performs functions like Nmap scanning, SMB enumeration, website downloading, and banner grabbing, organizing the results in a structured directory for easy access and further analysis.

**spray.sh**  
* A password spraying script that attempts to authenticate with a specified password for all users with a shell assigned in `/etc/passwd`. The script runs the `whoami` command under each user and halts upon detecting a successful login.
* 
### **System Administration & Network Tools**

**Cyber.sh**  - A script created for the Cyber Patriot competition back in 2017, to assist with workflows and now is open-source to the public:
- **firewall**: Installs and configures UFW (Uncomplicated Firewall), blocking insecure ports using `iptables`.
- **vis**: Edits the sudoers directory to modify user permissions through `visudo`.
- **ftp**: Hardens the FTP configuration by disabling anonymous logins and write permissions in `/etc/vsftpd.conf`.
- **homefolders**: Checks and secures user home directories and subdirectories.
- **user_accounts**: Creates a list of users, secures the root account, changes user passwords, and updates `/etc/passwd`, `/etc/group`, and `/etc/shadow`.
- **sys**: Adjusts sysctl settings to enhance security, including blocking SYN attacks and disabling IPv6.
- **media**: Clears unnecessary media files from the system.
- **hack**: Removes common hacking tools such as `nmap`, `vsftpd`, and `mysql` to reduce system vulnerabilities.

**Root Checker**  
* A simple script that checks if the current user has root (administrator) privileges. It's particularly useful for security audits to ensure necessary permissions are in place before running system-level tasks.

**UFW.sh**  
* Installs and configures Uncomplicated Firewall (UFW) on Linux systems, setting the default firewall policy to deny incoming connections. It also allows you to easily open specific ports (e.g., SSH, SMTP, Samba) by uncommenting relevant lines in the script.

**guest.sh**  
* Disables the guest account and hides users at the login screen for various Ubuntu versions (16.04, 14.04, 12.04). The script modifies LightDM configuration files, setting `allow-guest=false` and `greeter-hide-users=true`.

**sshd.sh**  - Enhances SSH server security by adjusting settings in `/etc/ssh/sshd_config`:
- **MOTD Banner**: Warns users that their connection is monitored.
- **IgnoreRhosts**: Prevents the use of `.rhosts` files for authentication.
- **UsePAM**: Enables Pluggable Authentication Modules (PAM) for more flexible authentication.
- **PrintMotd**: Displays the message of the day upon successful login.
- **UsePrivilegeSeparation**: Separates privileges to limit potential security vulnerabilities.
- **PermitRootLogin**: Disables root login over SSH.
- **X11Forwarding**: Disables X11 forwarding to reduce security risks.
- **PermitEmptyPasswords**: Disables empty passwords to enforce secure authentication.
- **Protocol**: Forces SSH to use version 2 (more secure than version 1).

---

## Setup and Installation

To use any of the scripts in this repository, follow these simple instructions:

### Prerequisites

Ensure you are running a Unix-based system (Linux, macOS) with Bash shell support. To check if you have Bash installed, run:
```bash
bash --version
```

### Installing Dependencies

These scripts are primarily self-contained, but if needed, install any additional dependencies using `apt`, `yum`, or the relevant package manager for your system.

### Running the Scripts

To execute any of these scripts, simply run the following command in your terminal:
```bash
bash script_name.sh
```

For example, to run `CTFGEN.sh`, use:
```bash
bash CTFGEN.sh
```

---
