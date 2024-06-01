#!/bin/bash

#==========================
# Basic Information
#==========================
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

#==========================
# Color
#==========================
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[  OK  ]${Font}"
ERROR="${Red}[FAILED]${Font}"

#==========================
# Print Colorful Text
#==========================
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${Red} $1 ${Font}"
}

#==========================
# Judge function
#==========================
judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 succeeded"
    sleep 1
  else
    print_error "$1 failed"
    exit 1
  fi
}

#==========================
# Get UUID function
#==========================
get_uuid() {
    local uuid_file="userid"

    if [[ -f "$uuid_file" ]]; then
        # If the file exists, read and return its content
        cat "$uuid_file"
    else
        # If the file does not exist, generate a new UUID and write it to the file
        local uuid
        uuid=$(cat /proc/sys/kernel/random/uuid)
        echo "$uuid" > "$uuid_file"
        echo "$uuid"
    fi
}

#==========================
# Port exist check function
#==========================
function port_exist_check() {
  if [[ 0 -eq $(sudo lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 is not in use"
    sleep 1
  else
    print_error "Warning: $1 is occupied"
    sudo lsof -i:"$1"
    print_error "Will kill the occupied process in 5s"
    sleep 5
    sudo lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | sudo xargs kill -9
    print_ok "Killed the occupied process"
    sleep 1
  fi
}

#==========================
# Begin of the installation
#==========================
clear
cd ~
echo "The command you are running is deploying tea on Ubuntu $(lsb_release -sc)."
echo "This may introduce non-open-source software to your system."
print_ok "Please press [ENTER] to continue, or press CTRL+C to cancel."
read

#==========================
# Check if the DNS is correct
#==========================
read -rp "Enter your domain(eg: myserver.southeastasia.cloudapp.azure.com):" domain
print_ok "Getting the IP of $domain ..."
domain_ip=$(dig +short ${domain} | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | head -n 1)
judge "Got the IP of domain is $domain_ip"

print_ok "Getting the local IP of this server ..."
local_ipv4=$(curl -4 ip.sb)
judge "Got the local IP of this server is $local_ipv4"

if [[ $domain_ip == $local_ipv4 ]]; then
  print_ok "Domain name resolution IP address is the same as the local IP address"
else
  print_error "The IP address resolved by the domain name does not match the local IP address"
  print_error "Are you sure to continue the installation? Enter [y/N] to continue"
  case $install in
  [yY][eE][sS] | [yY])
    print_ok "Continue the installation"
    ;;
  *)
    print_error "Installation terminated"
    exit 1
    ;;
  esac
fi

#==========================
# Ensure Ubuntu 22.04
#==========================
print_ok "Ensure you are Ubuntu 22.04..."
if ! lsb_release -a | grep "Ubuntu 22.04" > /dev/null; then
  print_error "You are not using Ubuntu 22.04. Please upgrade your system to 22.04 and try again."
  exit 1
fi
judge "Ensure you are Ubuntu 22.04"

#==========================
# Allow user to use sudo
#==========================
if ! sudo grep -q "$USER ALL=(ALL) NOPASSWD:ALL" /etc/sudoers.d/$USER; then
  print_ok "Adding $USER to sudoers..."
  sudo mkdir -p /etc/sudoers.d
  sudo touch /etc/sudoers.d/$USER
  echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/$USER
  judge "Add $USER to sudoers"
fi

#==========================
# Test network
#==========================
print_ok "Testing network..."
if ! curl -s --head  --request GET http://www.google.com/generate_204 | grep "204" > /dev/null; then
  print_error "You are not able to access Internet. Please check your network and try again!"
  exit 1
fi
judge "Test network"

#==========================
# Check port 80 & 443
#==========================
print_ok "Checking port 80 & 443..."
port_exist_check 80
port_exist_check 443
judge "Check port 80 & 443"

#==========================
# Remove ubuntu-advantage advertisement
#==========================
print_ok "Removing ubuntu-advantage advertisement..."
sudo rm /var/lib/ubuntu-advantage/messages/* > /dev/null 2>&1
print_ok "Remove ubuntu-advantage advertisement"

#==========================
# Remove i386 architecture
#==========================
print_ok "Removing i386 architecture..."
sudo dpkg --remove-architecture i386 || true
judge "Remove i386 architecture"

#==========================
# Remove snap
#==========================
print_ok "Removing snap..."
sudo killall -9 firefox > /dev/null 2>&1
sudo snap remove firefox > /dev/null 2>&1
sudo snap remove snap-store > /dev/null 2>&1
sudo snap remove gtk-common-themes > /dev/null 2>&1
sudo snap remove snapd-desktop-integration > /dev/null 2>&1
sudo snap remove bare > /dev/null 2>&1
sudo systemctl disable --now snapd
DEBIAN_FRONTEND=noninteractive sudo apt purge -y snapd
sudo rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /usr/lib/snapd ~/snap
cat << EOF | sudo tee -a /etc/apt/preferences.d/no-snap.pref
Package: snapd
Pin: release a=*
Pin-Priority: -10
EOF
sudo chown root:root /etc/apt/preferences.d/no-snap.pref
judge "Remove snap"

#==========================
# Set apt sources
#==========================
print_ok "Setting apt sources..."
#sudo add-apt-repository ppa:longsleep/golang-backports -y
sudo add-apt-repository -y multiverse -n
sudo add-apt-repository -y universe -n
sudo add-apt-repository -y restricted -n
judge "Add multiverse, universe, restricted"

#==========================
# Update apt sources
#==========================
print_ok "Installing basic packages..."
sudo systemctl daemon-reload
DEBIAN_FRONTEND=noninteractive sudo apt update
DEBIAN_FRONTEND=noninteractive sudo apt install -y ca-certificates wget gpg curl apt-transport-https software-properties-common gnupg net-tools git lsb-release vim nano curl aria2 ffmpeg iputils-ping dnsutils zip unzip jq golang-go debian-keyring debian-archive-keyring
judge "Install wget,gpg,curl,apt-transport-https,software-properties-common,gnupg,net-tools,git,lsb-release,vim,nano,curl,aria2,ffmpeg,iputils-ping,dnsutils,zip,unzip,jq,golang-go,debian-keyring,debian-archive-keyring"

#==========================
# Enable BBR
#==========================
enable_bbr_force()
{
    echo "BBR not enabled. Enabling BBR..."
    echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
    sysctl -p
    judge "Enable BBR"
}
sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr ||  enable_bbr_force
print_ok "BBR enabled"

#==========================
# Enable Cake
#==========================
enable_cake()
{
    echo "Cake not enabled. Enabling Cake..."
    echo 'net.core.default_qdisc=cake' | sudo tee /etc/sysctl.conf
    sudo sysctl -p
    judge "Enable Cake"
}
sysctl net.core.default_qdisc | grep -q cake ||  enable_cake
print_ok "Cake enabled"

#==========================
# Set timezone
#==========================
echo "Setting timezone..."
sudo timedatectl set-timezone UTC

#==========================
# Upgrade packages
#==========================
print_ok "Upgrading packages..."
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y --allow-downgrades
judge "Upgrade packages"

#==========================
# Enable UFW for 22,80 & 443, UDP & TCP
#==========================
print_ok "Enabling UFW..."
DEBIAN_FRONTEND=noninteractive sudo apt install -y ufw
sudo ufw allow 22,80,443/tcp
sudo ufw allow 22,80,443/udp
echo "y" | sudo ufw enable
judge "Enable UFW"

#==========================
# Building Caddy
#==========================
print_ok "Installing Caddy..."
DEBIAN_FRONTEND=noninteractive sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
DEBIAN_FRONTEND=noninteractive sudo apt update
DEBIAN_FRONTEND=noninteractive sudo apt install caddy
judge "Install Caddy"

#==========================
# Deploy Tracer on Port 8080
#==========================
print_ok "Deploying Tracer on Port 8080..."
port_exist_check 8080
judge "Check port 8080"
curl -sL https://gitlab.aiursoft.cn/aiursoft/tracer/-/raw/master/install.sh | sudo bash -s 8080
judge "Deploy Tracer"
sudo systemctl restart tracer
judge "Restart Tracer"

#==========================
# Setup reverse proxy
#==========================
print_ok "Setting up reverse proxy from $domain to Tracer(localhost:8080)..."
sudo bash -c "cat > /etc/caddy/Caddyfile" <<EOF
{
        email nobody@nodomain.com
        log {
                output file /var/log/caddy/caddy.log {
                        roll_size 1gb
                        roll_uncompressed
                }
                level info
        }
        servers :443 {
                listener_wrappers {
                        http_redirect
                        tls
                }
        }
}

(hsts) {
        header Strict-Transport-Security max-age=63072000
}

$domain {
        import hsts
        encode zstd gzip
        reverse_proxy http://localhost:8080 {
        }

        reverse_proxy /admin http://localhost:10000 {
        }
}
EOF
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
judge "Setup cadddy reverse proxy"
sudo systemctl restart caddy
judge "Restart caddy"

#==========================
# Install xray
#==========================
print_ok "Installing xray..."
sudo bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
sudo touch /usr/local/etc/xray/config.json
sudo systemctl restart xray.service
judge "Install xray"

#==========================
# Setup xray
#==========================
print_ok "Setting up xray..."
uuid=$(get_uuid)
sudo bash -c "cat > /usr/local/etc/xray/config.json" <<EOF
{
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 10000,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/admin"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
port_exist_check 10000
judge "Check port 10000"
sudo systemctl restart xray.service
judge "Setup xray"

#==========================
# Output connection information
#==========================
print_ok "Connection information:"
print_ok "Domain: $domain"
print_ok "UUID: $uuid"
print_ok "Tracer: https://$domain"
print_ok "Xray: wss://$domain:10000"
print_ok "URL (TLS+Websocket)"
print_ok "vless://$uuid@$domain?host=$domain&path=%2Fadmin&type=ws&encryption=none&security=tls&sni=$domain#$domain"

#==========================
# Optimize system
#==========================
if [ ! -f "/etc/sysctl.conf" ]; then
  sudo touch /etc/sysctl.conf
fi
sudo sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
sudo sed -i '/fs.file-max/d' /etc/sysctl.conf
sudo sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
sudo sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
sudo sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf

echo "net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
#net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

print_ok "Program completed, enjoy your tea! And it's suggested to restart the server."