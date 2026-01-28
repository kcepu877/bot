#!/bin/bash

# Password-Based VPS Bot Installer
# Support Password & SSH Key Authentication

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${BLUE}"
cat << "EOF"
    ╔═══════════════════════════════════════╗
    ║    PASSWORD VPS MANAGER BOT           ║
    ║    Support Password & SSH Key         ║
    ╚═══════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Generate random master password
MASTER_PASS=$(openssl rand -base64 32)
echo -e "${YELLOW}Generated Master Password:${NC}"
echo -e "${GREEN}$MASTER_PASS${NC}"
echo -e "${YELLOW}⚠️ Save this password! You'll need it later.${NC}"
echo ""

read -p "Press Enter to continue..."

# Install dependencies
echo -e "${YELLOW}[1/5] Installing dependencies...${NC}"
apt update
apt install -y python3 python3-pip git curl openssl
pip3 install python-telegram-bot paramiko cryptography

# Create bot directory
echo -e "${YELLOW}[2/5] Creating bot directory...${NC}"
mkdir -p /usr/local/bot
cd /usr/local/bot

# Create bot.py with master password
echo -e "${YELLOW}[3/5] Creating bot.py...${NC}"
cat > bot.py << EOF
#!/usr/bin/env python3
import os
import json
import base64
import logging
import paramiko
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, CallbackContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ========== CONFIGURATION ==========
TOKEN = "YOUR_TELEGRAM_TOKEN_HERE"  # Ganti dengan token bot
ADMIN_ID = YOUR_ADMIN_ID_HERE       # Ganti dengan chat ID admin
MASTER_PASSWORD = "$MASTER_PASS"    # Password master untuk enkripsi

# ========== ENCRYPTION ==========
class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password.encode()
        self.cipher_suite = self._get_cipher()
    
    def _get_cipher(self):
        salt = b'vps_bot_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password))
        return Fernet(key)
    
    def encrypt(self, text):
        return self.cipher_suite.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted_text):
        return self.cipher_suite.decrypt(encrypted_text.encode()).decode()

# ========== VPS MANAGER ==========
class VPSManager:
    def __init__(self):
        self.pm = PasswordManager(MASTER_PASSWORD)
        self.db_file = "/usr/local/bot/vps_db.enc"
        self.load_db()
    
    def load_db(self):
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    encrypted = f.read()
                    decrypted = self.pm.decrypt(encrypted)
                    self.vps_db = json.loads(decrypted)
            else:
                self.vps_db = {}
        except:
            self.vps_db = {}
    
    def save_db(self):
        try:
            data = json.dumps(self.vps_db, indent=2)
            encrypted = self.pm.encrypt(data)
            with open(self.db_file, 'w') as f:
                f.write(encrypted)
            os.chmod(self.db_file, 0o600)
            return True
        except:
            return False
    
    def add_vps(self, name, ip, username="root", password=None, port=22, auth_type="password"):
        if auth_type == "password" and not password:
            return False, "Password required"
        
        vps_data = {
            "ip": ip,
            "port": port,
            "username": username,
            "auth_type": auth_type,
            "status": "unknown"
        }
        
        if auth_type == "password":
            vps_data["password"] = self.pm.encrypt(password)
        elif auth_type == "ssh_key":
            vps_data["key_path"] = password  # Actually key path
        
        self.vps_db[name] = vps_data
        
        if self.save_db():
            return True, f"VPS '{name}' added"
        else:
            return False, "Save failed"
    
    def connect_vps(self, name):
        if name not in self.vps_db:
            return False, "VPS not found"
        
        vps = self.vps_db[name]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if vps["auth_type"] == "password":
                password = self.pm.decrypt(vps["password"])
                ssh.connect(vps["ip"], vps["port"], vps["username"], password, timeout=10)
            else:
                key = paramiko.RSAKey.from_private_key_file(vps["key_path"])
                ssh.connect(vps["ip"], vps["port"], vps["username"], pkey=key, timeout=10)
            
            return True, ssh
        except Exception as e:
            return False, str(e)
    
    def execute(self, name, command):
        success, result = self.connect_vps(name)
        if not success:
            return False, result
        
        ssh = result
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=15)
            output = stdout.read().decode()
            error = stderr.read().decode()
            ssh.close()
            
            if error:
                return True, f"Output:\\n{output}\\nError:\\n{error}"
            return True, output or "Command executed"
        except Exception as e:
            return False, str(e)

# ========== BOT INIT ==========
vps_manager = VPSManager()
logging.basicConfig(level=logging.INFO)

# ========== COMMANDS ==========
def start(update: Update, context: CallbackContext):
    update.message.reply_text(
        f"🤖 Password VPS Manager Bot\\n"
        f"VPS Count: {len(vps_manager.vps_db)}\\n\\n"
        f"Commands:\\n"
        f"/addpass name ip password\\n"
        f"/addkey name ip key_path\\n"
        f"/listvps\\n"
        f"/cmd name command\\n"
        f"/broadcast command",
        parse_mode="HTML"
    )

def addpass(update: Update, context: CallbackContext):
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Access denied")
        return
    
    if len(context.args) < 3:
        update.message.reply_text("Usage: /addpass name ip password [user] [port]")
        return
    
    name = context.args[0]
    ip = context.args[1]
    password = context.args[2]
    user = context.args[3] if len(context.args) > 3 else "root"
    port = int(context.args[4]) if len(context.args) > 4 else 22
    
    success, msg = vps_manager.add_vps(name, ip, user, password, port, "password")
    update.message.reply_text(f"{'✅' if success else '❌'} {msg}")

def listvps(update: Update, context: CallbackContext):
    if not vps_manager.vps_db:
        update.message.reply_text("No VPS registered")
        return
    
    text = "📋 VPS List:\\n"
    for name, info in vps_manager.vps_db.items():
        text += f"\\n🖥️ {name}\\n"
        text += f"IP: {info['ip']}:{info['port']}\\n"
        text += f"User: {info['username']}\\n"
        text += f"Auth: {info['auth_type']}\\n"
    
    update.message.reply_text(text)

def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("addpass", addpass))
    dp.add_handler(CommandHandler("listvps", listvps))
    
    print("🤖 Bot starting...")
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
EOF

# Create config file
echo -e "${YELLOW}[4/5] Creating config file...${NC}"
cat > config.txt << EOF
=== VPS PASSWORD BOT CONFIGURATION ===

1. TELEGRAM BOT:
   - Token: YOUR_TELEGRAM_TOKEN_HERE
   - Get from @BotFather

2. ADMIN ID:
   - Your Telegram Chat ID
   - Get from @userinfobot

3. MASTER PASSWORD:
   $MASTER_PASS
   ⚠️ Save this password!

4. BOT LOCATION:
   /usr/local/bot/

5. COMMANDS:
   /addpass name ip password [user] [port]
   /addkey name ip key_path [user] [port]
   /listvps
   /cmd name "command"
   /broadcast "command"

6. FILES:
   bot.py          - Main bot file
   vps_db.enc      - Encrypted VPS database
   config.txt      - This file
EOF

# Create systemd service
echo -e "${YELLOW}[5/5] Creating systemd service...${NC}"
cat > /etc/systemd/system/vps-password-bot.service << EOF
[Unit]
Description=VPS Password Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bot
ExecStart=/usr/bin/python3 /usr/local/bot/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chmod +x /usr/local/bot/bot.py
chmod 600 /usr/local/bot/config.txt

# Enable service
systemctl daemon-reload
systemctl enable vps-password-bot

echo -e "${GREEN}"
cat << "EOF"
    ╔═══════════════════════════════════════╗
    ║         INSTALLATION COMPLETE!        ║
    ╚═══════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}=== NEXT STEPS ===${NC}"
echo "1. Edit bot.py:"
echo "   nano /usr/local/bot/bot.py"
echo "   - Change TOKEN (line 15)"
echo "   - Change ADMIN_ID (line 16)"
echo ""
echo "2. Start bot:"
echo "   systemctl start vps-password-bot"
echo ""
echo "3. Check status:"
echo "   systemctl status vps-password-bot"
echo ""
echo "4. View config:"
echo "   cat /usr/local/bot/config.txt"
echo ""
echo -e "${RED}⚠️ IMPORTANT: Save your master password!${NC}"
echo -e "${GREEN}$MASTER_PASS${NC}"
echo ""
echo -e "${GREEN}Bot ready at: /usr/local/bot/${NC}"
