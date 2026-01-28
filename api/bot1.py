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

# Konfigurasi
TOKEN = "7747621243:AAH2nkriS_uohnMnj30Gwj5Zsmuv0dfDHiA"
ADMIN_ID = 7114686701
VPS_DB_FILE = "/usr/local/bot/vps_db.enc"  # Database terenkripsi
MASTER_PASSWORD = "Seaker877@00"  # Ganti dengan password kuat!

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== ENCRYPTION FUNCTIONS ==========

class PasswordManager:
    """Manager untuk enkripsi password"""
    
    def __init__(self, master_password):
        self.master_password = master_password.encode()
        self.cipher_suite = self._get_cipher()
    
    def _get_cipher(self):
        """Generate cipher dari master password"""
        salt = b'salt_'  # Bisa diganti dengan salt random
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password))
        return Fernet(key)
    
    def encrypt_password(self, password):
        """Enkripsi password"""
        return self.cipher_suite.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Dekripsi password"""
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()

# ========== VPS MANAGER ==========

class VPSPasswordManager:
    """Manager VPS dengan password authentication"""
    
    def __init__(self, password_manager):
        self.pm = password_manager
        self.db_file = VPS_DB_FILE
        self.load_db()
    
    def load_db(self):
        """Load database terenkripsi"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    encrypted_data = f.read()
                    decrypted_data = self.pm.cipher_suite.decrypt(encrypted_data.encode())
                    self.vps_db = json.loads(decrypted_data.decode())
            else:
                self.vps_db = {}
        except Exception as e:
            logger.error(f"Error loading database: {e}")
            self.vps_db = {}
    
    def save_db(self):
        """Simpan database terenkripsi"""
        try:
            data_json = json.dumps(self.vps_db, indent=2)
            encrypted_data = self.pm.cipher_suite.encrypt(data_json.encode())
            
            with open(self.db_file, 'w') as f:
                f.write(encrypted_data.decode())
            
            # Set permission ke 600
            os.chmod(self.db_file, 0o600)
            return True
        except Exception as e:
            logger.error(f"Error saving database: {e}")
            return False
    
    def add_vps_password(self, name, ip, port=22, username="root", password=None):
        """Tambahkan VPS dengan password"""
        if not password:
            return False, "Password diperlukan"
        
        # Enkripsi password
        encrypted_password = self.pm.encrypt_password(password)
        
        self.vps_db[name] = {
            "ip": ip,
            "port": port,
            "username": username,
            "password_encrypted": encrypted_password,
            "auth_type": "password",
            "status": "unknown",
            "last_check": None
        }
        
        if self.save_db():
            return True, f"VPS '{name}' berhasil ditambahkan"
        else:
            return False, "Gagal menyimpan database"
    
    def add_vps_sshkey(self, name, ip, port=22, username="root", key_path=None):
        """Tambahkan VPS dengan SSH key"""
        self.vps_db[name] = {
            "ip": ip,
            "port": port,
            "username": username,
            "key_path": key_path,
            "auth_type": "ssh_key",
            "status": "unknown",
            "last_check": None
        }
        
        if self.save_db():
            return True, f"VPS '{name}' berhasil ditambahkan (SSH Key)"
        else:
            return False, "Gagal menyimpan database"
    
    def test_connection(self, name):
        """Test koneksi ke VPS"""
        if name not in self.vps_db:
            return False, "VPS tidak ditemukan"
        
        vps = self.vps_db[name]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if vps["auth_type"] == "password":
                # Decrypt password
                decrypted_password = self.pm.decrypt_password(vps["password_encrypted"])
                ssh.connect(vps["ip"], port=vps["port"], 
                          username=vps["username"], password=decrypted_password,
                          timeout=10)
            
            elif vps["auth_type"] == "ssh_key":
                key_path = vps.get("key_path", "~/.ssh/id_rsa")
                key_path = os.path.expanduser(key_path)
                
                if os.path.exists(key_path):
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                    ssh.connect(vps["ip"], port=vps["port"], 
                              username=vps["username"], pkey=key,
                              timeout=10)
                else:
                    return False, f"SSH key tidak ditemukan: {key_path}"
            
            # Test command
            stdin, stdout, stderr = ssh.exec_command("echo 'Connection Test OK'")
            output = stdout.read().decode().strip()
            
            ssh.close()
            return True, f"Koneksi berhasil: {output}"
            
        except paramiko.AuthenticationException:
            return False, "Authentication failed - Password salah"
        except paramiko.SSHException as e:
            return False, f"SSH Error: {str(e)}"
        except Exception as e:
            return False, f"Connection Error: {str(e)}"
    
    def execute_command(self, name, command, timeout=15):
        """Eksekusi command via SSH dengan password"""
        if name not in self.vps_db:
            return False, "VPS tidak ditemukan"
        
        vps = self.vps_db[name]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if vps["auth_type"] == "password":
                decrypted_password = self.pm.decrypt_password(vps["password_encrypted"])
                ssh.connect(vps["ip"], port=vps["port"], 
                          username=vps["username"], password=decrypted_password,
                          timeout=timeout, banner_timeout=20)
            
            elif vps["auth_type"] == "ssh_key":
                key_path = vps.get("key_path", "~/.ssh/id_rsa")
                key_path = os.path.expanduser(key_path)
                
                if os.path.exists(key_path):
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                    ssh.connect(vps["ip"], port=vps["port"], 
                              username=vps["username"], pkey=key,
                              timeout=timeout)
                else:
                    return False, f"SSH key tidak ditemukan: {key_path}"
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            ssh.close()
            
            if error:
                return True, f"Output:\n{output}\n\nError:\n{error}"
            return True, output if output else "Command executed successfully"
            
        except paramiko.AuthenticationException:
            return False, "❌ Authentication failed - Password mungkin salah"
        except paramiko.SSHException as e:
            return False, f"❌ SSH Error: {str(e)}"
        except Exception as e:
            return False, f"❌ Error: {str(e)}"
    
    def get_vps_info(self, name):
        """Dapatkan info VPS"""
        if name not in self.vps_db:
            return None
        
        vps = self.vps_db[name].copy()
        
        # Jangan expose password
        if "password_encrypted" in vps:
            vps["password_encrypted"] = "***ENCRYPTED***"
        
        return vps

# ========== TELEGRAM HANDLERS ==========

# Inisialisasi
pm = PasswordManager(MASTER_PASSWORD)
vps_manager = VPSPasswordManager(pm)

def start(update: Update, context: CallbackContext):
    """Command: /start"""
    keyboard = [
        [InlineKeyboardButton("➕ Add VPS (Password)", callback_data="add_vps_pass")],
        [InlineKeyboardButton("🔑 Add VPS (SSH Key)", callback_data="add_vps_key")],
        [InlineKeyboardButton("📊 Check All VPS", callback_data="check_all")],
        [InlineKeyboardButton("⚡ Quick Actions", callback_data="quick_actions")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    update.message.reply_text(
        f"🤖 <b>Password-Based VPS Manager</b>\n"
        f"📊 Total VPS: {len(vps_manager.vps_db)}\n"
        f"🔐 Authentication: Password/SSH Key\n\n"
        f"Password disimpan dengan enkripsi!",
        parse_mode="HTML",
        reply_markup=reply_markup
    )

def add_vps_password_handler(update: Update, context: CallbackContext):
    """Handler untuk menambah VPS dengan password"""
    query = update.callback_query
    query.answer()
    
    query.edit_message_text(
        "Untuk menambah VPS dengan password:\n\n"
        "<code>/addpass nama ip password [port] [user]</code>\n\n"
        "Contoh:\n"
        "<code>/addpass vps1 192.168.1.1 mypassword123 22 root</code>\n\n"
        "⚠️ Password akan dienkripsi dan disimpan dengan aman!",
        parse_mode="HTML"
    )

def addpass_command(update: Update, context: CallbackContext):
    """Command: /addpass"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if len(context.args) < 3:
        update.message.reply_text(
            "Usage: /addpass <nama> <ip> <password> [port] [username]\n"
            "Contoh: /addpass vps1 192.168.1.1 P@ssw0rd123 22 root"
        )
        return
    
    name = context.args[0]
    ip = context.args[1]
    password = context.args[2]
    port = int(context.args[3]) if len(context.args) > 3 else 22
    username = context.args[4] if len(context.args) > 4 else "root"
    
    # Tambah VPS
    update.message.reply_text(f"🔐 Adding VPS '{name}' with password...")
    success, message = vps_manager.add_vps_password(name, ip, port, username, password)
    
    if success:
        # Test connection
        update.message.reply_text(f"🔗 Testing connection to {name}...")
        test_success, test_msg = vps_manager.test_connection(name)
        
        if test_success:
            update.message.reply_text(
                f"✅ {message}\n"
                f"🔗 Connection: {test_msg}"
            )
        else:
            update.message.reply_text(
                f"⚠️ {message}\n"
                f"🔗 Connection test failed: {test_msg}\n\n"
                f"Pastikan:\n"
                f"1. Password benar\n"
                f"2. SSH port terbuka\n"
                f"3. User memiliki akses"
            )
    else:
        update.message.reply_text(f"❌ {message}")

def add_vps_key_handler(update: Update, context: CallbackContext):
    """Handler untuk menambah VPS dengan SSH key"""
    query = update.callback_query
    query.answer()
    
    query.edit_message_text(
        "Untuk menambah VPS dengan SSH key:\n\n"
        "<code>/addkey nama ip [port] [user] [key_path]</code>\n\n"
        "Contoh:\n"
        "<code>/addkey vps2 192.168.1.2 22 root ~/.ssh/id_rsa</code>\n\n"
        "⚠️ SSH key harus sudah di-setup di VPS target!",
        parse_mode="HTML"
    )

def addkey_command(update: Update, context: CallbackContext):
    """Command: /addkey"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if len(context.args) < 2:
        update.message.reply_text(
            "Usage: /addkey <nama> <ip> [port] [username] [key_path]\n"
            "Contoh: /addkey vps2 192.168.1.2 22 root ~/.ssh/id_rsa"
        )
        return
    
    name = context.args[0]
    ip = context.args[1]
    port = int(context.args[2]) if len(context.args) > 2 else 22
    username = context.args[3] if len(context.args) > 3 else "root"
    key_path = context.args[4] if len(context.args) > 4 else "~/.ssh/id_rsa"
    
    # Tambah VPS
    update.message.reply_text(f"🔑 Adding VPS '{name}' with SSH key...")
    success, message = vps_manager.add_vps_sshkey(name, ip, port, username, key_path)
    
    if success:
        # Test connection
        update.message.reply_text(f"🔗 Testing connection to {name}...")
        test_success, test_msg = vps_manager.test_connection(name)
        
        if test_success:
            update.message.reply_text(
                f"✅ {message}\n"
                f"🔗 Connection: {test_msg}"
            )
        else:
            update.message.reply_text(
                f"⚠️ {message}\n"
                f"🔗 Connection test failed: {test_msg}"
            )
    else:
        update.message.reply_text(f"❌ {message}")

def check_all_vps(update: Update, context: CallbackContext):
    """Check status semua VPS"""
    query = update.callback_query
    query.answer()
    
    if not vps_manager.vps_db:
        query.edit_message_text("❌ Tidak ada VPS terdaftar")
        return
    
    status_text = "<b>🔍 CHECKING ALL VPS...</b>\n\n"
    query.edit_message_text(status_text, parse_mode="HTML")
    
    results = []
    online_count = 0
    
    for name, info in vps_manager.vps_db.items():
        success, message = vps_manager.test_connection(name)
        
        if success:
            emoji = "🟢"
            online_count += 1
            status = "ONLINE"
            
            # Get basic info
            success_info, info_msg = vps_manager.execute_command(name, "hostname && uptime -p")
            if success_info:
                info_lines = info_msg.split('\n')[:2]
                extra_info = "\n".join(info_lines)
            else:
                extra_info = "Connected"
        else:
            emoji = "🔴"
            status = "OFFLINE"
            extra_info = message[:50] + "..." if len(message) > 50 else message
        
        results.append(f"{emoji} <b>{name}</b> ({info['auth_type']})\n")
        results.append(f"IP: <code>{info['ip']}</code>\n")
        results.append(f"Status: {status}\n")
        results.append(f"Info: {extra_info}\n")
        results.append("─" * 25 + "\n")
    
    summary = f"\n📊 <b>SUMMARY:</b> {online_count}/{len(vps_manager.vps_db)} VPS Online"
    
    # Kirim per batch (Telegram limit)
    full_text = "<b>📊 VPS STATUS REPORT</b>\n\n" + "".join(results) + summary
    
    if len(full_text) > 4000:
        # Split menjadi 2 pesan
        half = len(results) // 2
        part1 = results[:half]
        part2 = results[half:]
        
        query.edit_message_text(
            "<b>📊 VPS STATUS REPORT (Part 1)</b>\n\n" + "".join(part1),
            parse_mode="HTML"
        )
        context.bot.send_message(
            chat_id=query.message.chat_id,
            text="<b>📊 VPS STATUS REPORT (Part 2)</b>\n\n" + "".join(part2) + summary,
            parse_mode="HTML"
        )
    else:
        query.edit_message_text(full_text, parse_mode="HTML")

def quick_actions_menu(update: Update, context: CallbackContext):
    """Menu quick actions"""
    query = update.callback_query
    query.answer()
    
    keyboard = [
        [
            InlineKeyboardButton("🔄 Restart Xray All", callback_data="restart_all_xray"),
            InlineKeyboardButton("📈 System Info All", callback_data="sysinfo_all")
        ],
        [
            InlineKeyboardButton("💾 Backup All", callback_data="backup_all"),
            InlineKeyboardButton("🧹 Clean Logs All", callback_data="clean_logs_all")
        ],
        [
            InlineKeyboardButton("🖥️ Select VPS", callback_data="select_vps_menu")
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        "⚡ <b>Quick Actions</b>\nPilih aksi untuk semua VPS:",
        parse_mode="HTML",
        reply_markup=reply_markup
    )

def execute_on_all_vps(update: Update, context: CallbackContext, command, description):
    """Eksekusi command ke semua VPS"""
    query = update.callback_query
    query.answer()
    
    if not vps_manager.vps_db:
        query.edit_message_text("❌ Tidak ada VPS terdaftar")
        return
    
    query.edit_message_text(f"🚀 {description} pada {len(vps_manager.vps_db)} VPS...")
    
    results = []
    success_count = 0
    
    for name in vps_manager.vps_db.keys():
        success, result = vps_manager.execute_command(name, command)
        
        if success:
            success_count += 1
            emoji = "✅"
            result_preview = result[:80] + "..." if len(result) > 80 else result
        else:
            emoji = "❌"
            result_preview = result[:80] + "..." if len(result) > 80 else result
        
        results.append(f"{emoji} <b>{name}</b>\n<pre>{result_preview}</pre>\n")
    
    summary = f"\n📊 <b>Results:</b> {success_count}/{len(vps_manager.vps_db)} successful"
    full_text = f"<b>📢 {description} Complete</b>\n\n" + "".join(results) + summary
    
    # Split jika terlalu panjang
    if len(full_text) > 4000:
        query.edit_message_text(full_text[:4000], parse_mode="HTML")
        context.bot.send_message(
            chat_id=query.message.chat_id,
            text=full_text[4000:],
            parse_mode="HTML"
        )
    else:
        query.edit_message_text(full_text, parse_mode="HTML")

def select_vps_menu(update: Update, context: CallbackContext):
    """Menu pilih VPS untuk aksi spesifik"""
    query = update.callback_query
    query.answer()
    
    if not vps_manager.vps_db:
        query.edit_message_text("❌ Tidak ada VPS terdaftar")
        return
    
    keyboard = []
    
    # Group VPS by status
    online_vps = []
    offline_vps = []
    
    for name in vps_manager.vps_db.keys():
        success, _ = vps_manager.test_connection(name)
        if success:
            online_vps.append(name)
        else:
            offline_vps.append(name)
    
    # Online VPS
    if online_vps:
        keyboard.append([InlineKeyboardButton("🟢 ONLINE VPS", callback_data="header")])
        for name in online_vps[:10]:  # Max 10 per section
            keyboard.append([
                InlineKeyboardButton(f"🖥️ {name}", callback_data=f"vps_action_{name}")
            ])
    
    # Offline VPS
    if offline_vps:
        keyboard.append([InlineKeyboardButton("🔴 OFFLINE VPS", callback_data="header")])
        for name in offline_vps[:10]:
            keyboard.append([
                InlineKeyboardButton(f"💀 {name}", callback_data=f"vps_action_{name}")
            ])
    
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="quick_actions")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        "🖥️ <b>Select VPS for Action</b>\n"
        f"Total: {len(vps_manager.vps_db)} VPS\n"
        f"Online: {len(online_vps)} | Offline: {len(offline_vps)}",
        parse_mode="HTML",
        reply_markup=reply_markup
    )

def vps_action_menu(update: Update, context: CallbackContext):
    """Menu aksi untuk VPS tertentu"""
    query = update.callback_query
    query.answer()
    
    vps_name = query.data.replace("vps_action_", "")
    
    # Save selected VPS in context
    context.user_data["selected_vps"] = vps_name
    
    keyboard = [
        [
            InlineKeyboardButton("📊 Status", callback_data=f"status_{vps_name}"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"restart_{vps_name}")
        ],
        [
            InlineKeyboardButton("📋 Logs", callback_data=f"logs_{vps_name}"),
            InlineKeyboardButton("👥 Users", callback_data=f"users_{vps_name}")
        ],
        [
            InlineKeyboardButton("💾 Backup", callback_data=f"backup_{vps_name}"),
            InlineKeyboardButton("⚙️ Custom", callback_data=f"custom_{vps_name}")
        ],
        [
            InlineKeyboardButton("🔧 Services", callback_data=f"services_{vps_name}"),
            InlineKeyboardButton("📈 Resources", callback_data=f"resources_{vps_name}")
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="select_vps_menu")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        f"🖥️ <b>VPS: {vps_name}</b>\n"
        f"IP: <code>{vps_manager.vps_db[vps_name]['ip']}</code>\n"
        f"Auth: {vps_manager.vps_db[vps_name]['auth_type']}\n\n"
        "Pilih aksi:",
        parse_mode="HTML",
        reply_markup=reply_markup
    )

def execute_vps_action(update: Update, context: CallbackContext):
    """Eksekusi aksi pada VPS tertentu"""
    query = update.callback_query
    query.answer()
    
    data = query.data
    vps_name = data.split("_")[1]  # Format: action_vpsname
    
    # Map aksi ke command
    commands = {
        "status": "hostname && uptime && free -h && df -h",
        "restart": "systemctl restart xray",
        "logs": "tail -20 /var/log/xray/error.log",
        "users": "who",
        "backup": "/usr/local/sbin/backup now 2>&1",
        "services": "systemctl status xray nginx ssh 2>&1 | head -20",
        "resources": "top -bn1 | head -20"
    }
    
    action = data.split("_")[0]
    
    if action == "custom":
        query.edit_message_text(
            f"Untuk custom command ke {vps_name}:\n\n"
            f"<code>/cmd {vps_name} your_command_here</code>\n\n"
            f"Contoh:\n"
            f"<code>/cmd {vps_name} apt update && apt upgrade -y</code>",
            parse_mode="HTML"
        )
        return
    
    if action not in commands:
        query.edit_message_text(f"Aksi '{action}' tidak dikenali")
        return
    
    command = commands[action]
    query.edit_message_text(f"🚀 Executing {action} on {vps_name}...")
    
    success, result = vps_manager.execute_command(vps_name, command)
    
    if success:
        query.edit_message_text(
            f"✅ <b>{action.capitalize()} Result ({vps_name}):</b>\n"
            f"<pre>{result[:3000]}</pre>",
            parse_mode="HTML"
        )
    else:
        query.edit_message_text(
            f"❌ <b>Failed on {vps_name}:</b>\n"
            f"<code>{result}</code>",
            parse_mode="HTML"
        )

def custom_command(update: Update, context: CallbackContext):
    """Command: /cmd <vps> <command>"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if len(context.args) < 2:
        update.message.reply_text(
            "Usage: /cmd <vps_name> <command>\n"
            "Contoh: /cmd vps1 'apt update && apt upgrade -y'\n\n"
            "Gunakan quotes untuk command panjang!"
        )
        return
    
    vps_name = context.args[0]
    command = " ".join(context.args[1:])
    
    if vps_name not in vps_manager.vps_db:
        update.message.reply_text(f"❌ VPS '{vps_name}' tidak ditemukan")
        return
    
    update.message.reply_text(f"🚀 Executing command on {vps_name}...")
    
    success, result = vps_manager.execute_command(vps_name, command)
    
    if success:
        # Split result jika terlalu panjang
        if len(result) > 3000:
            update.message.reply_text(
                f"✅ <b>Result from {vps_name} (Part 1):</b>\n"
                f"<pre>{result[:3000]}</pre>",
                parse_mode="HTML"
            )
            update.message.reply_text(
                f"✅ <b>Result from {vps_name} (Part 2):</b>\n"
                f"<pre>{result[3000:6000]}</pre>",
                parse_mode="HTML"
            )
        else:
            update.message.reply_text(
                f"✅ <b>Result from {vps_name}:</b>\n"
                f"<pre>{result}</pre>",
                parse_mode="HTML"
            )
    else:
        update.message.reply_text(
            f"❌ <b>Failed on {vps_name}:</b>\n"
            f"<code>{result}</code>",
            parse_mode="HTML"
        )

def broadcast_command(update: Update, context: CallbackContext):
    """Command: /broadcast <command>"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if not context.args:
        update.message.reply_text(
            "Usage: /broadcast <command>\n"
            "Contoh: /broadcast 'systemctl restart xray'\n\n"
            "⚠️ Command akan dieksekusi di SEMUA VPS!"
        )
        return
    
    command = " ".join(context.args)
    
    if not vps_manager.vps_db:
        update.message.reply_text("❌ Tidak ada VPS terdaftar")
        return
    
    update.message.reply_text(
        f"📢 Broadcasting command to {len(vps_manager.vps_db)} VPS...\n"
        f"Command: <code>{command[:100]}</code>",
        parse_mode="HTML"
    )
    
    results = []
    success_count = 0
    
    for name in vps_manager.vps_db.keys():
        success, result = vps_manager.execute_command(name, command)
        
        if success:
            success_count += 1
            emoji = "✅"
        else:
            emoji = "❌"
        
        result_preview = result[:80] + "..." if len(result) > 80 else result
        results.append(f"{emoji} <b>{name}</b>\n<pre>{result_preview}</pre>\n")
    
    summary = f"\n📊 <b>Broadcast Complete:</b> {success_count}/{len(vps_manager.vps_db)} successful"
    
    # Kirim hasil
    result_text = "<b>📢 Broadcast Results</b>\n\n" + "".join(results) + summary
    
    if len(result_text) > 4000:
        # Split message
        update.message.reply_text(result_text[:4000], parse_mode="HTML")
        update.message.reply_text(result_text[4000:8000], parse_mode="HTML")
    else:
        update.message.reply_text(result_text, parse_mode="HTML")

def list_vps(update: Update, context: CallbackContext):
    """Command: /listvps"""
    if not vps_manager.vps_db:
        update.message.reply_text("❌ Tidak ada VPS terdaftar")
        return
    
    text = "<b>📋 REGISTERED VPS LIST</b>\n\n"
    
    for name, info in vps_manager.vps_db.items():
        # Test connection
        success, _ = vps_manager.test_connection(name)
        
        emoji = "🟢" if success else "🔴"
        auth_icon = "🔐" if info["auth_type"] == "password" else "🔑"
        
        text += f"{emoji} {auth_icon} <b>{name}</b>\n"
        text += f"IP: <code>{info['ip']}:{info['port']}</code>\n"
        text += f"User: {info['username']}\n"
        text += f"Auth: {info['auth_type']}\n"
        text += f"Status: {'Online' if success else 'Offline'}\n"
        text += "─" * 25 + "\n"
    
    text += f"\n📊 Total: {len(vps_manager.vps_db)} VPS"
    
    update.message.reply_text(text, parse_mode="HTML")

def change_password(update: Update, context: CallbackContext):
    """Command: /changepass <vps> <new_password>"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if len(context.args) < 2:
        update.message.reply_text(
            "Usage: /changepass <vps_name> <new_password>\n"
            "Contoh: /changepass vps1 NewP@ssw0rd123"
        )
        return
    
    vps_name = context.args[0]
    new_password = context.args[1]
    
    if vps_name not in vps_manager.vps_db:
        update.message.reply_text(f"❌ VPS '{vps_name}' tidak ditemukan")
        return
    
    # Update password
    encrypted_password = pm.encrypt_password(new_password)
    vps_manager.vps_db[vps_name]["password_encrypted"] = encrypted_password
    
    if vps_manager.save_db():
        update.message.reply_text(f"✅ Password untuk '{vps_name}' berhasil diubah!")
    else:
        update.message.reply_text(f"❌ Gagal mengubah password")

def delete_vps(update: Update, context: CallbackContext):
    """Command: /delvps <vps_name>"""
    if update.effective_user.id != ADMIN_ID:
        update.message.reply_text("❌ Akses ditolak!")
        return
    
    if not context.args:
        update.message.reply_text("Usage: /delvps <vps_name>")
        return
    
    vps_name = context.args[0]
    
    if vps_name in vps_manager.vps_db:
        del vps_manager.vps_db[vps_name]
        vps_manager.save_db()
        update.message.reply_text(f"✅ VPS '{vps_name}' berhasil dihapus!")
    else:
        update.message.reply_text(f"❌ VPS '{vps_name}' tidak ditemukan")

def main():
    """Main function"""
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    
    # Command handlers
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("addpass", addpass_command))
    dp.add_handler(CommandHandler("addkey", addkey_command))
    dp.add_handler(CommandHandler("listvps", list_vps))
    dp.add_handler(CommandHandler("cmd", custom_command))
    dp.add_handler(CommandHandler("broadcast", broadcast_command))
    dp.add_handler(CommandHandler("changepass", change_password))
    dp.add_handler(CommandHandler("delvps", delete_vps))
    
    # Callback handlers
    dp.add_handler(CallbackQueryHandler(add_vps_password_handler, pattern="add_vps_pass"))
    dp.add_handler(CallbackQueryHandler(add_vps_key_handler, pattern="add_vps_key"))
    dp.add_handler(CallbackQueryHandler(check_all_vps, pattern="check_all"))
    dp.add_handler(CallbackQueryHandler(quick_actions_menu, pattern="quick_actions"))
    dp.add_handler(CallbackQueryHandler(
        lambda u,c: execute_on_all_vps(u,c, "systemctl restart xray", "Restart Xray All"),
        pattern="restart_all_xray"
    ))
    dp.add_handler(CallbackQueryHandler(
        lambda u,c: execute_on_all_vps(u,c, "hostname && uptime && free -h", "System Info All"),
        pattern="sysinfo_all"
    ))
    dp.add_handler(CallbackQueryHandler(select_vps_menu, pattern="select_vps_menu"))
    dp.add_handler(CallbackQueryHandler(vps_action_menu, pattern="^vps_action_"))
    dp.add_handler(CallbackQueryHandler(execute_vps_action, pattern="^(status_|restart_|logs_|users_|backup_|services_|resources_)"))
    dp.add_handler(CallbackQueryHandler(start, pattern="back_main"))
    
    # Start bot
    updater.start_polling()
    
    # Send startup notification
    try:
        total_vps = len(vps_manager.vps_db)
        online_count = sum(1 for name in vps_manager.vps_db.keys() 
                          if vps_manager.test_connection(name)[0])
        
        updater.bot.send_message(
            ADMIN_ID,
            f"🔐 Password-Based VPS Bot Aktif!\n"
            f"📊 Total VPS: {total_vps}\n"
            f"🟢 Online: {online_count}\n"
            f"🔴 Offline: {total_vps - online_count}\n\n"
            f"Gunakan /start untuk memulai"
        )
    except:
        pass
    
    updater.idle()

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════╗
    ║   PASSWORD-BASED VPS MANAGER BOT      ║
    ║   No SSH Key Required!                ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Warning about master password
    if MASTER_PASSWORD == "your_master_password_here":
        print("⚠️  WARNING: Please change MASTER_PASSWORD in the code!")
        print("⚠️  Current password is default and insecure!")
    
    main()
