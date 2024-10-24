#!/bin/bash

# Color Variables for aesthetic output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No color

# Function to display usage
usage() {
    echo -e "${YELLOW}Usage: $0 --ctfname <CTF-Name> --target <Target-IP>${NC}"
    exit 1
}

# Function to perform Nmap scan
nmap_scan() {
    local ip=$1
    local ctfname=$2
    echo -e "${YELLOW}[*] Running Nmap scan on $ip...${NC}"

    # Run the Nmap scan and save the output to a file
    nmap -p- -sC -sV -Pn --open $ip -oN "$ctfname/enumeration/nmap/initial_scan.txt"

    echo -e "${GREEN}[+] Nmap scan completed. Output saved to $ctfname/enumeration/nmap/initial_scan.txt${NC}"

    # Debugging: Display the relevant Nmap output
    echo -e "${YELLOW}[*] Nmap output for open ports:${NC}"
    cat "$ctfname/enumeration/nmap/initial_scan.txt"

    # Check if port 445 is open
    if grep -q "445/tcp[[:space:]]*open" "$ctfname/enumeration/nmap/initial_scan.txt"; then
        echo -e "${GREEN}[+] Port 445 is open. Running SMB enumeration...${NC}"
        smb_check "$ip" "$ctfname"
    else
        echo -e "${RED}[-] Port 445 is not open. Skipping SMB and SID enumeration.${NC}"
    fi

    # Check if port 80 is open and download the website
    if grep -q "80/tcp[[:space:]]*open" "$ctfname/enumeration/nmap/initial_scan.txt"; then
        echo -e "${GREEN}[+] Port 80 is open. Downloading website...${NC}"
        curl_website "$ip" "$ctfname"
    else
        echo -e "${RED}[-] Port 80 is not open. Skipping website download.${NC}"
    fi
}

# Function to check SMB and SID enumeration
smb_check() {
    local ip=$1
    local ctfname=$2
    echo -e "${YELLOW}[*] Running SMB enumeration...${NC}"

    # Run smbclient and save the output
    smbclient -L "\\\\$ip\\" -N > "$ctfname/enumeration/smb/smbclient_output.txt"
    echo -e "${GREEN}[+] SMB client output saved to $ctfname/enumeration/smb/smbclient_output.txt${NC}"

    # Run impacket-lookupsid and save the output
    impacket-lookupsid anonymous@$ip -no-pass > "$ctfname/enumeration/smb/lookupsid_output.txt"
    echo -e "${GREEN}[+] SID enumeration output saved to $ctfname/enumeration/smb/lookupsid_output.txt${NC}"
}

# Function to download website using curl
curl_website() {
    local ip=$1
    local ctfname=$2
    echo -e "${YELLOW}[*] Downloading entire website from port 80...${NC}"

    # Run curl --mirror to download the website
    mkdir -p "$ctfname/enumeration/http"
    curl --mirror http://$ip -o "$ctfname/enumeration/http/site_download"
    echo -e "${GREEN}[+] Website downloaded and saved to $ctfname/enumeration/http/site_download${NC}"
}

# Function to perform netcat banner grabbing
banner_grab() {
    local ip=$1
    local port=$2
    echo -e "${YELLOW}[*] Grabbing banner on $ip:$port...${NC}"
    nc -nv -w 3 $ip $port > "$ctfname/enumeration/nc/$port.txt"
    echo -e "${GREEN}[+] Banner for $ip:$port saved to $ctfname/enumeration/nc/$port.txt${NC}"
}

# Parse command-line arguments
while [ "$1" != "" ]; do
    case $1 in
        --ctfname ) shift
            ctfname=$1
            ;;
        --target ) shift
            target=$1
            ;;
        * ) usage
            ;;
    esac
    shift
done

# Validate inputs
if [ -z "$ctfname" ] || [ -z "$target" ]; then
    usage
fi

# Create necessary directories
echo -e "${YELLOW}[*] Creating directory structure for $ctfname...${NC}"
mkdir -p "$ctfname/enumeration/nmap" "$ctfname/enumeration/smb" "$ctfname/enumeration/http" "$ctfname/enumeration/nc" \
         "$ctfname/loot" "$ctfname/exploit" "$ctfname/report" "$ctfname/downloaded_files" "$ctfname/notes"
echo -e "${GREEN}[+] Directory structure created.${NC}"

# Ping target to check connectivity
echo -e "${YELLOW}[*] Pinging $target to check connectivity...${NC}"
ping -c 4 $target

# Run Nmap scan and follow up with SMB or web checks based on results
nmap_scan $target $ctfname

# Perform banner grabbing on key ports
echo -e "${YELLOW}[*] Starting banner grabbing...${NC}"
for port in 22 53 80 445; do
    banner_grab $target $port
done
