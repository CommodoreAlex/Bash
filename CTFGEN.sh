#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to create directories
create_directories() {
    local ctfname=$1
    echo -e "${YELLOW}[*] Creating directories for $ctfname...${NC}"
    mkdir -p "$ctfname"/{enumeration/{nmap,smb,http,nc},loot,exploit,report,downloaded_files,notes}
    echo -e "${GREEN}[+] Directories created under $ctfname:${NC}"
}

# Function to perform ping check
ping_target() {
    local ip=$1
    echo -e "${YELLOW}[*] Pinging $ip (4 counts)...${NC}"
    ping -c 4 $ip
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Host $ip is reachable.${NC}"
    else
        echo -e "${RED}[-] Host $ip is unreachable.${NC}"
    fi
}

# Function for netcat banner grabbing with a timeout (non-blocking)
netcat_scan() {
    local ip=$1
    local ports=(22 53 80 445)
    local timeout=3
    echo -e "${YELLOW}[*] Performing netcat banner grabbing for ports 22, 53, 80, 445 on $ip...${NC}"
    for port in "${ports[@]}"; do
        echo -e "${YELLOW}[*] Grabbing banner on port $port (timeout: ${timeout}s)...${NC}"
        # Non-blocking banner grabbing with timeout and no user input
        (echo -e "GET / HTTP/1.0\r\n" | nc -nv -w $timeout $ip $port) > "$ctfname/enumeration/nc/banner_$port.txt" 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Banner grabbed for port $port. Saved to banner_$port.txt.${NC}"
        else
            echo -e "${RED}[-] Failed to grab banner for port $port.${NC}"
        fi
    done
}

# Function to perform nmap scan
nmap_scan() {
    local ip=$1
    echo -e "${YELLOW}[*] Running Nmap scan on $ip...${NC}"
    nmap -p- -sC -sV -Pn --open $ip -oN "$ctfname/enumeration/nmap/initial_scan.txt"
    echo -e "${GREEN}[+] Nmap scan completed. Output saved to $ctfname/enumeration/nmap/initial_scan.txt${NC}"
}

# Function to check if port 445 is open and run smbclient if true
smb_check() {
    local ip=$1
    local ctfname=$2
    echo -e "${YELLOW}[*] Checking if port 445 is open on $ip...${NC}"
    
    nc -zv $ip 445 2>&1 | grep -q succeeded
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Port 445 is open. Running smbclient...${NC}"
        mkdir -p "$ctfname/enumeration/smb"
        smbclient -L \\\\$ip\\ > "$ctfname/enumeration/smb/smb_enum.txt"
        echo -e "${GREEN}[+] SMB client enumeration saved to $ctfname/enumeration/smb/smb_enum.txt${NC}"
    else
        echo -e "${RED}[-] Port 445 is not open. Skipping SMB client enumeration.${NC}"
    fi
}

# Function to check if port 80 is open and download the entire website using wget if true
http_check() {
    local ip=$1
    local ctfname=$2
    echo -e "${YELLOW}[*] Checking if port 80 is open on $ip using Nmap...${NC}"
    
    # Check if port 80 is open using nmap
    nmap -p 80 --open $ip | grep "80/tcp open" > /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Port 80 is open. Downloading website using wget...${NC}"
        mkdir -p "$ctfname/enumeration/http"
        wget -r -P "$ctfname/enumeration/http" http://$ip
        echo -e "${GREEN}[+] Website downloaded and saved to $ctfname/enumeration/http${NC}"
    else
        echo -e "${RED}[-] Port 80 is not open. Skipping website download.${NC}"
    fi
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --ctfname) ctfname="$2"; shift ;;
        --target) ip="$2"; shift ;;
        --scan-target) scan_target=true ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Ensure ctfname and target IP are provided
if [[ -z "$ctfname" || -z "$ip" ]]; then
    echo -e "${RED}Usage: ctfgen --ctfname <name> --target <ip> [--scan-target]${NC}"
    exit 1
fi

# Create directories
create_directories "$ctfname"

# Ping the target
ping_target "$ip"

# Run netcat scans
netcat_scan "$ip"

# Optionally run nmap scan
if [[ "$scan_target" = true ]]; then
    nmap_scan "$ip"
fi

# Check port 445 and run smbclient if open
smb_check "$ip" "$ctfname"

# Check port 80 and download website if open
http_check "$ip" "$ctfname"
