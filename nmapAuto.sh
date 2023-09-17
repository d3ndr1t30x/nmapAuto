#!/bin/bash
# by 21y4d

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

SECONDS=0

usage(){
  echo -e ""
  echo -e "${RED}Usage: $0 <TARGET-IP> <TYPE>"
  echo -e "${YELLOW}"
  echo -e "Scan Types:"
  echo -e "\tQuick: Shows all open ports quickly (~15 seconds)"
  echo -e "\tBasic: Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)"
  echo -e "\tUDP: Runs \"Basic\" on UDP ports (~5 minutes)"
  echo -e "\tFull: Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)"
  echo -e "\tVulns: Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)"
  echo -e "\tRecon: Suggests recon commands, then prompts to automatically run them"
  echo -e "\tAll: Runs all the scans (~20-30 minutes)"
  echo -e ""
  exit 1
}

header(){
  echo -e ""

  if [ "$2" == "All" ]; then
    echo -e "${YELLOW}Running all scans on $1"
  else
    echo -e "${YELLOW}Running a $2 scan on $1"
  fi

  subnet=$(echo "$1" | cut -d "." -f 1,2,3)".0"

  checkPing=$(checkPing "$1")
  nmapType="nmap -Pn"

  ttl=$(echo "${checkPing}" | tail -n 1)
  if [[ $(echo "${ttl}") != "nmap -Pn" ]]; then
    osType="$(checkOS "$ttl")"
    echo -e "${NC}"
    echo -e "${GREEN}Host is likely running $osType"
    echo -e "${NC}"
  fi

  echo -e ""
  echo -e ""
}

assignPorts(){
  if [ -f nmap/Quick_"$1".nmap ]; then
    basicPorts=$(cat nmap/Quick_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
  fi

  if [ -f nmap/Full_"$1".nmap ]; then
    if [ -f nmap/Quick_"$1".nmap ]; then
      allPorts=$(cat nmap/Quick_"$1".nmap nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1)
    else
      allPorts=$(cat nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1)
    fi
  fi

  if [ -f nmap/UDP_"$1".nmap ]; then
    udpPorts=$(cat nmap/UDP_"$1".nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
    if [[ "$udpPorts" == "Al" ]]; then
      udpPorts=""
    fi
  fi
}

checkPing(){
  pingTest=$(ping -c 1 -W 3 "$1" | grep ttl)
  if [[ -z $pingTest ]]; then
    echo "nmap -Pn"
  else
    echo "nmap"
    ttl=$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)
    echo "${ttl}"
  fi
}

checkOS(){
  if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
    echo "OpenBSD/Cisco/Oracle"
  elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
    echo "Windows"
  elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
    echo "Linux"
  else
    echo "Unknown OS!"
  fi
}

cmpPorts(){
  oldIFS=$IFS
  IFS=','
  touch nmap/cmpPorts_"$1".txt

  for i in $(echo "${allPorts}")
  do
    if [[ "$i" =~ ^($(echo "${basicPorts}" | sed 's/,/\|/g'))$ ]]; then
      :
    else
      echo -n "$i," >> nmap/cmpPorts_"$1".txt
    fi
  done

  extraPorts=$(cat nmap/cmpPorts_"$1".txt | tr "\n" "," | head -c-1)
  rm nmap/cmpPorts_"$1".txt
  IFS=$oldIFS
}

quickScan(){
  echo -e "${GREEN}---------------------Starting Nmap Quick Scan---------------------"
  echo -e "${NC}"

  $nmapType -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Quick_"$1".nmap "$1"

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/Quick_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  assignPorts "$1"

  echo -e ""
  echo -e ""
  echo -e ""
}

basicScan(){
  echo -e "${GREEN}---------------------Starting Nmap Basic Scan---------------------"
  echo -e "${NC}"

  if [ -z $(echo "${basicPorts}") ]; then
    echo -e "${YELLOW}No ports in quick scan.. Skipping!"
  else
    $nmapType -sCV -p$(echo "${basicPorts}") -oN nmap/Basic_"$1".nmap "$1"
  fi

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/Basic_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  if [ -f nmap/Basic_"$1".nmap ] && [[ ! -z $(cat nmap/Basic_"$1".nmap | grep -w "Service Info: OS:") ]]; then
    serviceOS=$(cat nmap/Basic_"$1".nmap | grep -w "Service Info: OS:" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1)
    if [[ "$osType" != "$serviceOS"  ]]; then
      osType=$(echo "${serviceOS}")
      echo -e "${NC}"
      echo -e "${NC}"
      echo -e "${GREEN}OS Detection modified to: $osType"
      echo -e "${NC}"
    fi
  fi

  echo -e ""
  echo -e ""
  echo -e ""
}

UDPScan(){
  echo -e "${GREEN}----------------------Starting Nmap UDP Scan----------------------"
  echo -e "${NC}"

  $nmapType -sU --max-retries 1 --open -oN nmap/UDP_"$1".nmap "$1"
  assignPorts "$1"

  if [ ! -z $(echo "${udpPorts}") ]; then
    echo ""
    echo ""
    echo -e "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')"
    echo -e "${NC}"
    if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
      $nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
    else
      $nmapType -sCVU -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
    fi
  fi

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/UDP_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  echo -e ""
  echo -e ""
  echo -e ""
}

fullScan(){
  echo -e "${GREEN}---------------------Starting Nmap Full Scan----------------------"
  echo -e "${NC}"

  $nmapType -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Full_"$1".nmap "$1"
  assignPorts "$1"

  if [ -z $(echo "${basicPorts}") ]; then
    echo ""
    echo ""
    echo -e "${YELLOW}Making a script scan on all ports"
    echo -e "${NC}"
    $nmapType -sCV -p$(echo "${allPorts}") -oN nmap/Full_"$1".nmap "$1"
    assignPorts "$1"
  else
    cmpPorts "$1"
    if [ -z $(echo "${extraPorts}") ]; then
      echo ""
      echo ""
      allPorts=""
      echo -e "${YELLOW}No new ports"
      rm nmap/Full_"$1".nmap
      echo -e "${NC}"
    else
      echo ""
      echo ""
      echo -e "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')"
      echo -e "${NC}"
      $nmapType -sCV -p$(echo "${extraPorts}") -oN nmap/Full_"$1".nmap "$1"
      assignPorts "$1"
    fi
  fi

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/Full_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  echo -e ""
  echo -e ""
  echo -e ""
}

vulnsScan(){
  echo -e "${GREEN}---------------------Starting Nmap Vulns Scan---------------------"
  echo -e "${NC}"

  if [ -f nmap/Quick_"$1".nmap ]; then
    $nmapType -p$(echo "${basicPorts}") --script vuln -oN nmap/Vulns_"$1".nmap "$1"
  else
    $nmapType -p- --script vuln -oN nmap/Vulns_"$1".nmap "$1"
  fi

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/Vulns_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  echo -e ""
  echo -e ""
  echo -e ""
}

reconScan(){
  echo -e "${GREEN}---------------------Starting Recon Scan---------------------"
  echo -e "${NC}"

  echo -e "${YELLOW}Running Nmap scripts scan"
  echo -e "${NC}"
  $nmapType -sC -p$(echo "${basicPorts}") -oN nmap/Recon_"$1".nmap "$1"

  # Add this code to generate output files in multiple formats
  nmapCommand="$nmapType -oA nmap/Recon_"$1" "$1""  # XML, Nmap Script Output, grepable
  eval "$nmapCommand"

  # Optionally, add more formats like XML, JSON, etc., as needed

  echo -e ""
  echo -e ""
  echo -e ""

  if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
    echo -e "${YELLOW}Running vulners scan"
    echo -e "${NC}"
    $nmapType -sV --script vulners -p$(echo "${basicPorts}") -oN nmap/Recon_"$1".nmap "$1"

    # Add this code to generate output files in multiple formats
    nmapCommand="$nmapType -oA nmap/Recon_"$1" "$1""  # XML, Nmap Script Output, grepable
    eval "$nmapCommand"

    # Optionally, add more formats like XML, JSON, etc., as needed

    echo -e ""
    echo -e ""
    echo -e ""
  fi

  if [ -f /usr/share/nmap/scripts/vulscan/vulscan.nse ]; then
    echo -e "${YELLOW}Running vulscan scan"
    echo -e "${NC}"
    $nmapType -sV --script vulscan/vulscan -p$(echo "${basicPorts}") -oN nmap/Recon_"$1".nmap "$1"

    # Add this code to generate output files in multiple formats
    nmapCommand="$nmapType -oA nmap/Recon_"$1" "$1""  # XML, Nmap Script Output, grepable
    eval "$nmapCommand"

    # Optionally, add more formats like XML, JSON, etc., as needed

    echo -e ""
    echo -e ""
    echo -e ""
  fi
}

allScan(){
  header "$1" "All"
  quickScan "$1"
  basicScan "$1"
  UDPScan "$1"
  fullScan "$1"
  vulnsScan "$1"
  reconScan "$1"
}

# Check for necessary arguments
if [ "$#" -ne 2 ]; then
  usage
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root.${NC}"
  exit 1
fi

# Create necessary directories
mkdir -p nmap

# Main logic for scan types
case "$2" in
  "Quick")
    header "$1" "Quick"
    quickScan "$1"
    ;;
  "Basic")
    header "$1" "Basic"
    quickScan "$1"
    basicScan "$1"
    ;;
  "UDP")
    header "$1" "UDP"
    UDPScan "$1"
    ;;
  "Full")
    header "$1" "Full"
    fullScan "$1"
    ;;
  "Vulns")
    header "$1" "Vulns"
    vulnsScan "$1"
    ;;
  "Recon")
    header "$1" "Recon"
    reconScan "$1"
    ;;
  "All")
    allScan "$1"
    ;;
  *)
    usage
    ;;
esac

echo -e "${YELLOW}Script execution time: $((SECONDS / 60)) min $((SECONDS % 60)) sec"
echo -e "${NC}"
