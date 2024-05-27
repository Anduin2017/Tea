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
# Begin of the installation
#==========================
clear
cd ~
echo "The command you are running is deploying tea on Ubuntu $(lsb_release -sc)."
echo "This may introduce non-open-source software to your system."
print_ok "Please press [ENTER] to continue, or press CTRL+C to cancel."
read

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
sudo apt purge -y snapd
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
sudo add-apt-repository -y multiverse -n
sudo add-apt-repository -y universe -n
sudo add-apt-repository -y restricted -n
judge "Add multiverse, universe, restricted"

#==========================
# Update apt sources
#==========================
print_ok "Installing basic packages..."
sudo systemctl daemon-reload
sudo apt update
sudo apt install -y ca-certificates wget gpg curl apt-transport-https software-properties-common gnupg net-tools git lsb-release vim nano curl aria2 ffmpeg iputils-ping dnsutils zip unzip jq
judge "Install wget,gpg,curl,apt-transport-https,software-properties-common,gnupg,net-tools,git,lsb-release,vim,nano,curl,aria2,ffmpeg,iputils-ping,dnsutils,zip,unzip,jq"

#==========================
# Enable BBR
#==========================
enable_bbr_force()
{
    echo "BBR not enabled. Enabling BBR..."
    echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
    sysctl -p
}
sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr ||  enable_bbr_force

#==========================
# Set timezone
#==========================
echo "Setting timezone..."
sudo timedatectl set-timezone UTC

#==========================
# Upgrade packages
#==========================
print_ok "Upgrading packages..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt --purge autoremove -y
sleep 2
sudo DEBIAN_FRONTEND=noninteractive apt install --fix-broken  -y
sleep 2
sudo DEBIAN_FRONTEND=noninteractive apt install --fix-missing  -y
sleep 2
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a
sleep 2
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y --allow-downgrades
judge "Upgrade packages"

#==========================
# Enable UFW for 80 & 443, UDP & TCP
#==========================
print_ok "Enabling UFW..."
sudo apt install -y ufw
sudo ufw allow 22,80,443/tcp
sudo ufw allow 22,80,443/udp
echo "y" | sudo ufw enable
judge "Enable UFW"


#==========================
# Deploy Tracer on Port 8080
#==========================
print_ok "Deploying Tracer on Port 8080..."
curl -sL https://gitlab.aiursoft.cn/aiursoft/tracer/-/raw/master/install.sh | sudo bash -s 8080
judge "Deploy Tracer on Port 8080"

#==========================
# Install xray
#==========================
print_ok "Installing xray..."
sudo bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
sudo touch /usr/local/etc/xray/config.json
sudo systemctl restart xray.service
judge "Install xray"
