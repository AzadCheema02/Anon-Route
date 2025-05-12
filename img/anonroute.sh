#!/usr/bin/env bash

## General
#
# program information
readonly prog_name="Anon-Route"
readonly version="1.0.0"
readonly signature="Copyright (C) 2025"
readonly git_url="https://github.com/AzadCheema02/Anon-Route"

# set colors for stdout
export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export blue="$(tput setaf 4)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"

## Directories
readonly data_dir="/usr/share/Anon-Route/data"      # config files
readonly backup_dir="/var/lib/Anon-Route/backups"   # backups

## Network settings
#
# the UID that Tor runs as (varies from system to system)
# $(id -u debian-tor) #Debian/Ubuntu
readonly tor_uid="$(id -u debian-tor)"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_address="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


## Show program banner
banner() {

# Check if figlet is installed
if ! command -v figlet &> /dev/null
then
    echo "[*] figlet not found. Installing..."
    sudo apt-get update && sudo apt-get install figlet -y
fi

# Clear the screen
clear

# Display Anon-Route banner
echo -e "${green}$(figlet 'Anon-Route')${reset}"

    printf "${blue}${b}Version:${reset} ${green}1.0.0${reset}\n"
    printf "${yellow}=[ Transparent proxy through Tor${reset}\n"
    printf "${white}=[ Created by AZADVIR SINGH${reset}\n"
}


## Print a message and exit with (1) when an error occurs
die() {
    printf "${red}%s${reset}\\n" "[ERROR] $*" >&2
    exit 1
}


## Print information
info() {
    printf "${b}${blue}%s${reset} ${b}%s${reset}\\n" "::" "${@}"

}


## Print OK messages
msg() {
    printf "${b}${green}%s${reset} %s\\n\\n" "[OK]" "${@}"
}


## Check if the program run as a root
check_root() {
    if [[ "${UID}" -ne 0 ]]; then
        die "Please run this program as a root!"
    fi
}


## Display program version and License
print_version() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "${signature}"
    printf "%s\\n" "There is NO WARRANTY, to the extent permitted by law."
    exit 0
}


## Configure general settings
#
# - packages: tor, curl
# - program directories, see: ${data_dir}, ${backup_dir}
# - tor configuration file: /etc/tor/torrc
# - DNS settings: /etc/resolv.conf
setup_general() {
    info "Check program settings"

    # packages
    declare -a dependencies=('tor' 'curl')
    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "'${package}' isn't installed, exit"
        fi
    done

    # directories
    if [[ ! -d "${backup_dir}" ]]; then
        die "directory '${backup_dir}' not exist, run makefile first!"
    fi

    if [[ ! -d "${data_dir}" ]]; then
        die "directory '${data_dir}' not exist, run makefile first!"
    fi

    # replace torrc file
    if [[ ! -f /etc/tor/torrc ]]; then
        die "/etc/tor/torrc file not exist, check Tor configuration"
    fi

    printf "%s\\n" "Set /etc/tor/torrc"

    if ! cp -f /etc/tor/torrc "${backup_dir}/torrc.backup"; then
        die "can't backup '/etc/tor/torrc'"
    fi

    if ! cp -f "${data_dir}/torrc" /etc/tor/torrc; then
        die "can't copy new '/etc/tor/torrc'"
    fi

    # DNS settings: /etc/resolv.conf:
    #
    # write nameserver 127.0.0.1 to /etc/resolv.conf file
    # i.e. use Tor DNSPort (see: /etc/tor/torrc)
    printf "%s\\n" "Configure resolv.conf file to use Tor DNSPort"

    # backup current resolv.conf
    if ! cp /etc/resolv.conf "${backup_dir}/resolv.conf.backup"; then
        die "can't backup '/etc/resolv.conf'"
    fi

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf

    # reload systemd daemons
    printf "%s\\n" "Reload systemd daemons"
    systemctl --system daemon-reload
}


## iptables settings
#
# This function is used with args in start() and stop() functions
# for set/restore iptables.
#
# Usage: setup_iptables <arg>
#
# function args:
#       tor_proxy -> set rules for Tor transparent proxy
#       default   -> restore default rules
setup_iptables() {
    case "$1" in
        tor_proxy)
            printf "%s\\n" "Setting iptables rules for Tor transparent proxy"

            # Ensure required variables are set
            : "${trans_port:=9040}"
            : "${dns_port:=5353}"
            : "${virtual_address:=10.192.0.0/10}"
            : "${tor_uid:=$(id -u debian-tor)}"
            : "${non_tor:="192.168.0.0/16 10.0.0.0/8"}"  # Example local LANs

            ## Flush existing rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X

            ## Reset default policies
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT

            ### === NAT TABLE ===

            # Redirect .onion traffic
            iptables -t nat -A OUTPUT -d $virtual_address -p tcp --syn -j REDIRECT --to-ports $trans_port

            # Redirect local DNS queries to Tor's DNSPort
            iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp --dport 53 -j REDIRECT --to-ports $dns_port

            # Exempt Tor process, loopback, and local LANs
            iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
            iptables -t nat -A OUTPUT -o lo -j RETURN

            for lan in $non_tor; do
                iptables -t nat -A OUTPUT -d $lan -j RETURN
            done

            # Redirect remaining TCP traffic to Tor's TransPort
            iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $trans_port

            ### === FILTER TABLE ===

            ## INPUT chain
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -j DROP

            ## FORWARD chain
            iptables -A FORWARD -j DROP

            ## OUTPUT chain
            iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
            iptables -A OUTPUT -m state --state INVALID -j DROP
            iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

            # Allow new TCP connections from Tor process
            iptables -A OUTPUT -m owner --uid-owner $tor_uid -p tcp --syn -m state --state NEW -j ACCEPT

            # Allow loopback traffic
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -A OUTPUT -d 127.0.0.1/32 -j ACCEPT

            # Allow traffic to Tor TransPort (to avoid self-blocking)
            iptables -A OUTPUT -p tcp --dport $trans_port -j ACCEPT

            # Allow DNSPort (if used)
            iptables -A OUTPUT -p udp --dport $dns_port -j ACCEPT

            # Drop everything else
            iptables -A OUTPUT -j DROP

            ## Set default policies to DROP (secure by default)
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT DROP

            ;;
        
        default)
            printf "%s\\n" "Restoring default iptables rules"

            # Flush and reset to default ACCEPT policies
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            ;;
    esac
}



## Check public IP address
#
# Make an HTTP request to the ip api service on the list, if the
# first request fails try with the next, then print the IP address
check_ip() {
    echo "[🔍] Checking public IP and Tor status..."

    # Ensure required tools are available
    if ! command -v curl >/dev/null || ! command -v jq >/dev/null; then
        echo "[!] Required tools 'curl' or 'jq' are not installed."
        return 1
    fi

    echo -e "\n[🌐] Regular IP Information:"
    ipinfo_response=$(curl --silent --fail https://ipwho.is)

    if [[ $? -eq 0 && -n "$ipinfo_response" ]]; then
        ip=$(echo "$ipinfo_response" | jq -r '.ip')
        country=$(echo "$ipinfo_response" | jq -r '.country')
        region=$(echo "$ipinfo_response" | jq -r '.region')
        city=$(echo "$ipinfo_response" | jq -r '.city')
        isp=$(echo "$ipinfo_response" | jq -r '.connection.org')

        echo -e "IP:        $ip"
        if [[ "$country" == "Unknown" ]]; then
            echo -e "Location:  Unknown (May be anonymized or unresolvable)"
        else
            echo -e "Location:  $city, $region, $country"
        fi
        echo -e "ISP:       $isp"
    else
        echo "[!] Failed to fetch regular IP info"
    fi

    echo -e "\n[🧅] Tor IP Information:"
    tor_ipinfo_response=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://ipwho.is)

    if [[ $? -eq 0 && -n "$tor_ipinfo_response" ]]; then
        tor_ip=$(echo "$tor_ipinfo_response" | jq -r '.ip')
        tor_country=$(echo "$tor_ipinfo_response" | jq -r '.country')
        tor_region=$(echo "$tor_ipinfo_response" | jq -r '.region')
        tor_city=$(echo "$tor_ipinfo_response" | jq -r '.city')
        tor_isp=$(echo "$tor_ipinfo_response" | jq -r '.connection.org')

        echo -e "Tor IP:        $tor_ip"
        if [[ "$tor_country" == "Unknown" ]]; then
            echo -e "Tor Location:  Unknown (Likely a Tor exit node)"
        else
            echo -e "Tor Location:  $tor_city, $tor_region, $tor_country"
        fi
        echo -e "Tor ISP:       $tor_isp"
    else
        echo "[!] Failed to fetch Tor IP info (is Tor running?)"
    fi

    echo -e "\n[🔐] Tor Network Status:"
    torcheck=$(curl --silent --fail https://check.torproject.org)

    if echo "$torcheck" | grep -q "Congratulations. This browser is configured to use Tor."; then
        echo -e "[✔] You are connected through the Tor network"
    else
        echo -e "[✘] You are NOT using Tor"
    fi
}




## Check status of program and services
#
# - tor.service
# - tor settings (check if Tor works correctly)
# - public IP Address
check_status() {
    info "Check current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        msg "Tor service is active"
    else
        die "Tor service is not running! exit"
    fi

    # make an HTTP request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the HTML page to test connection
    # with Tor
    info "Check Tor network settings"

    # curl SOCKS options:
    #   --socks5 <host[:port]> SOCKS5 proxy on given host + port
    #   --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
    local hostport="localhost:9050"
    local url="https://check.torproject.org/"

    if curl --socks5 "${hostport}" --socks5-hostname "${hostport}" -s "${url}" | cat | grep -q "Congratulations"; then
        msg "Your system is configured to use Tor"
    else
        printf "${red}%s${reset}\\n\\n" "Your system is not using Tor!"
        printf "%s\\n" "try another Tor circuit with '${prog_name} --restart'"
        exit 1
    fi

    check_ip
}


## Start transparent proxy through Tor
start() {
    check_root

    # Exit if tor.service is already active
    if systemctl is-active tor.service >/dev/null 2>&1; then
        die "Tor service is already active, stop it first"
    fi

    banner
    sleep 2
    setup_general

    printf "\\n"
    info "Starting Transparent Proxy"

    # disable IPv6
    printf "%s\\n" "Disable IPv6 with sysctl"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

    # start tor.service
    printf "%s\\n" "Start Tor service"

    if ! systemctl start tor.service >/dev/null 2>&1; then
        die "can't start tor service, exit!"
    fi

    # set new iptables rules
    setup_iptables tor_proxy

    # check program status
    printf "\\n"
    check_status

    printf "\\n${b}${green}%s${reset} %s\\n" \
            "[OK]" "Transparent Proxy activated, your system is under Tor"
}


## Stop transparent proxy
#
# stop connection with Tor Network and return to clearnet navigation
stop() {
    check_root

    # don't run function if tor.service is NOT running!
    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Stopping Transparent Proxy"

        # resets default iptables rules
        setup_iptables default

        printf "%s\\n" "Stop tor service"
        systemctl stop tor.service

        # restore /etc/resolv.conf:
        #
        # restore file with resolvconf if exists otherwise copy the original
        # file from backup directory.
        printf "%s\\n" "Restore default DNS"

        if hash resolvconf 2>/dev/null; then
            resolvconf -u
        else
            cp "${backup_dir}/resolv.conf.backup" /etc/resolv.conf
        fi

        # enable IPv6
        printf "%s\\n" "Enable IPv6"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1

        # restore default /etc/tor/torrc
        printf "%s\\n" "Restore default /etc/tor/torrc"
        cp "${backup_dir}/torrc.backup" /etc/tor/torrc

        printf "\\n${b}${green}%s${reset} %s\\n" "[-]" "Transparent Proxy stopped"
        exit 0
    else
        die "Tor service is not running! exit"
    fi
}


## Restart
#
# restart tor.service (i.e. get new Tor exit node)
# and change public IP Address
restart() {
    check_root

    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Change IP address"

        systemctl restart tor.service
        sleep 1
        check_ip
        exit 0
    else
        die "Tor service is not running! exit"
    fi
}
## check IP Table Rules
show_iptables() {
    echo -e "${b}${blue}🛡️  Current iptables Rules:${reset}"
    sudo iptables -L -n -v --line-numbers
}

check_system_resources() {
    echo -e "\n--- System Resource Usage ---"

    # CPU usage
    echo -n "CPU Usage: "
    mpstat | grep "all" | awk '{print $3"%"}'

    # RAM usage
    echo -n "RAM Usage: "
    free -h | grep Mem | awk '{print $3 "/" $2 " (" $3/$2*100 "%)"}'

    # Disk usage
    echo -n "Disk Usage: "
    df -h | grep "^/dev" | awk '{print $1 ": " $5}'

    echo -e "\n--- Resource Check Completed ---"
}

rotate_tor_ip() {
    echo -e "\n--- Rotating IP ---"
    
    # Check if Tor is running
    if ! pgrep tor > /dev/null; then
        echo "Tor service is not running. Please start Tor first."
        return
    fi

    # Send the signal to Tor to get a new IP
    echo "Sending SIGINT to Tor to request new circuit (IP)..."
    tor --signal NEWNYM
    sleep 10  # Wait for the new IP to be assigned
    
    # Confirm the IP has changed
    echo "Checking current public IP..."
    curl -s ifconfig.me
    echo -e "\n--- IP Rotation Completed ---"
}


## Show help menù
usage() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "Kali Linux - Transparent proxy through Tor"
    printf "%s\\n\\n" "${signature}"

    printf "%s\\n\\n" "Usage: ${prog_name} [option]"

    printf "%s\\n\\n" "Options:"

    printf "%s\\n" "-h, --help      show this help message and exit"
    printf "%s\\n" "-t, --tor       start transparent proxy through tor"
    printf "%s\\n" "-c, --clearnet  reset iptables and return to clearnet navigation"
    printf "%s\\n" "-s, --status    check status of program and services"
    printf "%s\\n" "-i, --ipinfo    show public IP address"
    printf "%s\\n\\n" "-tb, --table   display current IP Table Rules"
    printf "%s\\n\\n" "-rc, --resource-chech   display  system's CPU, RAM, and disk usage performance"
    printf "%s\\n" "-rip, --rotate-ip      rotate the Tor IP automatically after 10 seconds"
    printf "%s\\n" "-r, --restart   restart tor service and change IP address"
    printf "%s\\n\\n" "-v, --version   display program version and exit"
    printf "%s\\n" "Project URL: ${git_url}"
    printf "%s\\n" "Report bugs: ${git_url}/issues"

    exit 0
}


## Main function
#
# Parse command line arguments and start program
main() {
    if [[ "$#" -eq 0 ]]; then
        printf "%s\\n" "${prog_name}: Argument required"
        printf "%s\\n" "Try '${prog_name} --help' for more information."
        exit 1
    fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -t | --tor)
                start
                ;;
            -c | --clearnet)
                stop
                ;;
            -r | --restart)
                restart
                ;;
            -s | --status)
                check_status
                ;;
            -i | --ipinfo)
                check_ip
                ;;
            -tb | --table)
                show_iptables
                ;;
            -rc | --resource-check)
                check_system_resources
                ;;
            -rip | --rotate-ip)
                rotate_tor_ip
                ;;
            -v | --version)
                print_version
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            -- | -* | *)
                printf "%s\\n" "${prog_name}: Invalid option '$1'"
                printf "%s\\n" "Try '${prog_name} --help' for more information."
                exit 1
                ;;
        esac
        exit 0
    done
}

# Call main
main "${@}"
