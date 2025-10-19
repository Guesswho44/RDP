#!/usr/bin/env bash
# premium-menu.sh
# Minimal VPN / Xray panel installer & menu for Debian 12 (original, free)
# WARNING: run as root

set -euo pipefail
LANG=C

# -------------------------
# Configuration & defaults
# -------------------------
DATA_DIR="/usr/local/vpn-panel"
XRAY_BIN="/usr/local/bin/xray"
DOMAIN_FILE="$DATA_DIR/domain"
CLIENTS_DIR="$DATA_DIR/clients"
VERSION="1.0.0-free"

# Colors
GREEN="\e[32m"; CYAN="\e[36m"; YEL="\e[33m"; RED="\e[31m"; RESET="\e[0m"

# Ensure directories
mkdir -p "$DATA_DIR" "$CLIENTS_DIR"

# -------------------------
# Utility functions
# -------------------------
cecho(){ echo -e "${CYAN}$*${RESET}"; }
info(){ echo -e "${GREEN}$*${RESET}"; }
warn(){ echo -e "${YEL}$*${RESET}"; }
err(){ echo -e "${RED}$*${RESET}"; }

# Check running as root
if [[ "$EUID" -ne 0 ]]; then
  err "Sila jalankan sebagai root (sudo)."
  exit 1
fi

# Get system info for display
get_os(){ awk -F= '/^PRETTY_NAME/{print $2}' /etc/os-release | tr -d '"' || echo "Debian"; }
get_ram(){ free -m | awk '/Mem:/{printf "%d MB",$2}'; }
get_cpu(){ lscpu | awk -F: '/^CPU\(s\):/{gsub(" ","",$2); print $2}' || echo "1"; }
get_ip(){ curl -sS https://ipinfo.io/ip || hostname -I | awk '{print $1}'; }
get_isp(){ curl -sS https://ipinfo.io/org | sed 's/,.*//' || echo "Unknown"; }
get_uptime(){ awk '{print int($1/3600)"h,"int(($1%3600)/60)"m"}' /proc/uptime; }
get_date(){ date +"%Y-%m-%d %H:%M:%S"; }

# -------------------------
# Installer functions
# -------------------------
install_prereq(){
  info "Mengemaskini repos & memasang pakej asas..."
  apt update -y
  apt install -y curl wget gnupg2 ca-certificates unzip xz-utils jq lsof net-tools iproute2 qrencode socat
}

install_vnstat(){
  if ! command -v vnstat >/dev/null 2>&1; then
    info "Memasang vnstat (bandwidth monitoring)..."
    apt install -y vnstat
    systemctl enable --now vnstat || true
  fi
}

install_xray_core(){
  if [[ -x "$XRAY_BIN" ]]; then
    info "Xray sudah ada, skip muat turun."
    return
  fi
  info "Muat turun xray-core (terbaru) dari GitHub releases..."
  latest_json=$(curl -sSfL "https://api.github.com/repos/XTLS/Xray-core/releases/latest")
  url=$(echo "$latest_json" | jq -r '.assets[] | select(.name | test("linux-64.zip")) | .browser_download_url' | head -n1)
  if [[ -z "$url" ]]; then
    warn "Gagal dapatkan URL automatik; cuba muat turun standard."
    url="https://github.com/XTLS/Xray-core/releases/latest/download/xray-linux-64.zip"
  fi
  tmpd=$(mktemp -d)
  pushd "$tmpd" >/dev/null
  curl -sSL "$url" -o xray.zip
  unzip -q xray.zip
  install -m 755 xray "$XRAY_BIN"
  popd >/dev/null
  rm -rf "$tmpd"
  info "Xray dipasang ke $XRAY_BIN"
}

setup_xray_service(){
  if [[ ! -x "$XRAY_BIN" ]]; then
    warn "xray tidak ditemui, skip service."
    return
  fi
  info "Membina systemd unit untuk xray..."
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=$XRAY_BIN run -config /etc/xray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p /etc/xray
  # default minimal config (users managed separately)
  cat > /etc/xray/config.json <<'EOF'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp"
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} }
  ]
}
EOF
  systemctl daemon-reload
  systemctl enable --now xray.service || true
  info "Xray service started (port 8443 vless default)."
}

install_openvpn(){
  info "Memasang OpenVPN (server) asas via apt..."
  apt install -y openvpn easy-rsa
  warn "Skrip ini tidak automatik buat konfigurasi penuh OpenVPN. Sila setup PKI/ovpn config mengikut keperluan."
}

install_wireguard(){
  info "Memasang WireGuard..."
  apt install -y wireguard
  warn "Sila konfigurasi /etc/wireguard/wg0.conf sendiri."
}

# -------------------------
# Account management
# -------------------------
create_ssh_user(){
  read -rp "Username SSH: " user
  read -rp "Tempoh hari (contoh 30): " days
  pass=$(openssl rand -base64 12)
  useradd -M -s /bin/false -e "$(date -d "+$days days" +%F)" "$user" || { err "Gagal create user"; return; }
  echo "$user:$pass" | chpasswd
  mkdir -p "$CLIENTS_DIR/$user"
  echo -e "user:$user\npass:$pass\nexpires:$(date -d "+$days days" +%F)" > "$CLIENTS_DIR/$user/info.txt"
  info "SSH user dibuat: $user (password: $pass)"
}

# --- Tambahan: Delete SSH User ---
delete_ssh_user(){
  read -rp "Masukkan username SSH yang ingin dipadam: " user
  if id "$user" &>/dev/null; then
    userdel -f "$user" && rm -rf "$CLIENTS_DIR/$user"
    info "User SSH '$user' telah dipadam."
  else
    warn "User tidak wujud."
  fi
}

create_xray_vless(){
  if [[ ! -x "$XRAY_BIN" ]]; then
    err "Xray belum dipasang. Pilih Install Xray dahulu."
    return
  fi
  read -rp "Nama klien (id ringkas): " CLIENT
  UUID=$(cat /proc/sys/kernel/random/uuid)
  read -rp "Tempoh hari (contoh 30): " DAYS
  EXP=$(date -d "+$DAYS days" +%F)
  jq --arg id "$UUID" '.inbounds[0].settings.clients += [{"id":$id,"email": "'"$CLIENT"'"}]' /etc/xray/config.json > /etc/xray/config.json.tmp \
    && mv /etc/xray/config.json.tmp /etc/xray/config.json
  systemctl restart xray.service || true
  mkdir -p "$CLIENTS_DIR/$CLIENT"
  cat > "$CLIENTS_DIR/$CLIENT/info.txt" <<EOF
id: $UUID
type: vless
port: 8443
host: $(get_ip)
expires: $EXP
EOF
  info "VLESS client dibuat: $CLIENT (id: $UUID)"
  echo
  echo -e "${YEL}VLESS link:${RESET} vless://${UUID}@$(get_ip):8443?encryption=none&security=auto#${CLIENT}"
}

# --- Tambahan: Delete Xray User ---
delete_xray_vless(){
  read -rp "Masukkan nama klien VLESS yang ingin dipadam: " CLIENT
  if grep -q "$CLIENT" /etc/xray/config.json; then
    sed -i "/$CLIENT/,+2d" /etc/xray/config.json
    rm -rf "$CLIENTS_DIR/$CLIENT"
    systemctl restart xray.service
    info "Client VLESS '$CLIENT' telah dipadam."
  else
    warn "Client tidak ditemui dalam config.json."
  fi
}

# --- Tambahan: Delete Alias & Trojan placeholder ---
delete_alias_user(){ delete_xray_vless; }
delete_trojan_user(){
  read -rp "Masukkan nama user Trojan yang ingin dipadam: " name
  warn "Fungsi delete trojan ($name) belum diimplement penuh — placeholder."
}

list_clients(){
  echo "Clients directory: $CLIENTS_DIR"
  ls -1 "$CLIENTS_DIR" || echo "(tiada)"
}

backup_data(){
  out="/root/vpn-panel-backup-$(date +%F).tar.gz"
  tar -czf "$out" -C "$DATA_DIR" . || { err "Backup gagal"; return; }
  info "Backup disimpan: $out"
}

restore_data(){
  read -rp "Path file backup (.tar.gz): " path
  if [[ ! -f "$path" ]]; then err "Fail tidak wujud"; return; fi
  tar -xzf "$path" -C "$DATA_DIR" || { err "Restore gagal"; return; }
  info "Restore selesai."
}

change_domain(){
  read -rp "Masukkan domain / hostname (contoh vpn.example.com): " dom
  echo "$dom" > "$DOMAIN_FILE"
  info "Domain disimpan: $dom"
}

update_script(){
  info "Mengemaskini skrip ini..."
  info "Skrip ini tidak ada mekanisma auto-update. Sila muat turun versi baru dari sumber anda."
}

# -------------------------
# Display menu
# -------------------------
draw_header(){
  clear
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}"
  printf "${CYAN}║%56s%6s║\n${RESET}" "  ❄ WELCOME TO PREMIUM SCRIPT ❄" ""
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}"
  printf "\n"
  printf "%-18s : %s\n" "OS" "$(get_os)"
  printf "%-18s : %s\n" "RAM" "$(get_ram)"
  printf "%-18s : %s\n" "CPU cores" "$(get_cpu)"
  printf "%-18s : %s\n" "ISP" "$(get_isp)"
  printf "%-18s : %s\n" "IP VPS" "$(get_ip)"
  printf "%-18s : %s\n" "UPTIME" "$(get_uptime)"
  if [[ -f "$DOMAIN_FILE" ]]; then
    printf "%-18s : %s\n" "DOMAIN" "$(cat $DOMAIN_FILE)"
  else
    printf "%-18s : %s\n" "DOMAIN" "-"
  fi
  printf "%-18s : %s\n" "DATE & TIME" "$(get_date)"
  printf "%-18s : %s\n" "VERSION CORE" "xray (local) & script ${VERSION}"
  echo
  echo -e "${CYAN}Service status:${RESET} $(systemctl is-active xray.service 2>/dev/null || echo inactive)"
  if command -v vnstat >/dev/null 2>&1; then
    echo -e "${CYAN}Server speed (sample):${RESET} $(vnstat -tr 1 2>/dev/null | awk '/rx rate|tx rate/{print $3" "$4}')"
  fi
  echo
  echo -e "${GREEN}VPN PANEL MENU${RESET}"
  echo -e "[01] SSH & OVPN"
  echo -e "[02] XRAY VMESS/VLESS"
  echo -e "[03] XRAY VLESS (alias)"
  echo -e "[04] XRAY TROJAN (placeholder)"
  echo -e ""
  echo -e "[05] MEDIA CHECKER (placeholder)"
  echo -e "[06] FEATURE SCRIPT (info)"
  echo -e "[07] ADD SWAP RAM"
  echo -e "[08] BACKUP & RESTORE"
  echo -e "[09] CHANGE COLOUR (placeholder)"
  echo -e "[10] BOT TELEGRAM (placeholder)"
  echo -e "[11] CHANGE DNS SERVER (placeholder)"
  echo -e ""
  echo -e "[12] CHANGE DOMAIN"
  echo -e "[13] LIMITS XRAY (placeholder)"
  echo -e "[14] MULTIPATH XRAY (placeholder)"
  echo -e "[15] CHANGE XRAY CORE"
  echo -e "[16] UPDATE SCRIPT"
  echo -e "[17] CHANGE PASSWORD (for script admin)"
  echo -e "[18] REBOOT SERVER"
  echo -e "[19] REGISTER IPVPS MENU (placeholder)"
  echo -e "[20] DNS MENU (placeholder)"
  echo -e "[x] Exit"
  echo
}

# -------------------------
# Add swap, password, etc.
# -------------------------
add_swap(){
  read -rp "Masukkan saiz swap (contoh 1G): " sz
  fallocate -l "$sz" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  info "Swap $sz ditambah."
}

change_password_script(){
  read -rp "Masukkan kata laluan baru untuk akses skrip: " pw
  echo "$pw" > "$DATA_DIR/.panel_pass"
  info "Password skrip disimpan."
}

# -------------------------
# Main loop
# -------------------------
while true; do
  draw_header
  read -rp "Select From option [1 - 20 or x]: " opt
  case "$opt" in
    1)
      echo "== SSH & OVPN Menu =="
      echo "1) Create SSH user"
      echo "2) Delete SSH user"
      echo "3) Install OpenVPN"
      read -rp "Choose: " sub
      case "$sub" in
        1) create_ssh_user;;
        2) delete_ssh_user;;
        3) install_openvpn;;
        *) warn "Invalid";;
      esac
      read -rp "Tekan Enter untuk kembali..."
      ;;
    2)
      echo "== XRAY VMESS/VLESS =="
      echo "1) Install Xray"
      echo "2) Create VLESS client"
      echo "3) Delete VLESS client"
      echo "4) List clients"
      read -rp "Choose: " sub
      case "$sub" in
        1) install_prereq; install_vnstat; install_xray_core; setup_xray_service;;
        2) create_xray_vless;;
        3) delete_xray_vless;;
        4) list_clients;;
        *) warn "Invalid";;
      esac
      read -rp "Tekan Enter untuk kembali..."
      ;;
    3)
      echo "== XRAY VLESS (alias) =="
      echo "1) Create Alias client"
      echo "2) Delete Alias client"
      read -rp "Choose: " sub
      case "$sub" in
        1) create_xray_vless;;
        2) delete_alias_user;;
        *) warn "Invalid";;
      esac
      read -rp "Tekan Enter..."
      ;;
    4)
      echo "== XRAY TROJAN (placeholder) =="
      echo "1) Delete Trojan user"
      read -rp "Choose: " sub
      case "$sub" in
        1) delete_trojan_user;;
        *) warn "Invalid";;
      esac
      read -rp "Tekan Enter..."
      ;;
    5) warn "Media checker: placeholder"; read -rp "Enter...";;
    6) echo "Feature script: This panel is minimal free version."; read -rp "Enter...";;
    7) add_swap; read -rp "Enter...";;
    8)
      echo "1) Backup Data"
      echo "2) Restore Data"
      read -rp "Choose: " sub
      case "$sub" in
        1) backup_data;;
        2) restore_data;;
        *) warn "Invalid";;
      esac
      read -rp "Enter...";;
    9) warn "Change colour: placeholder"; read -rp "Enter...";;
    10) warn "Bot Telegram: placeholder"; read -rp "Enter...";;
    11) warn "Change DNS server: placeholder"; read -rp "Enter...";;
    12) change_domain; read -rp "Enter...";;
    13) warn "Limits Xray: placeholder"; read -rp "Enter...";;
    14) warn "Multipath Xray: placeholder"; read -rp "Enter...";;
    15)
      echo "Change Xray core: reinstall latest"
      install_xray_core
      setup_xray_service
      read -rp "Enter...";;
    16) update_script; read -rp "Enter...";;
    17) change_password_script; read -rp "Enter...";;
    18) read -rp "Confirm reboot? (y/N): " c; [[ "$c" == "y" ]] && reboot || echo "Cancel";;
    19) warn "Register IPVPS menu: placeholder"; read -rp "Enter...";;
    20) warn "DNS menu: placeholder"; read -rp "Enter...";;
    x|X) info "Bye."; exit 0;;
    *) warn "Pilihan tidak dikenali";;
  esac
done
