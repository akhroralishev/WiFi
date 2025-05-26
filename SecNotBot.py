from scapy.all import arping
from telegram.ext import Updater, CommandHandler, MessageHandler, filters
from telegram import ReplyKeyboardMarkup
from mac_vendor_lookup import MacLookup
import json
import time
import subprocess
import re
from threading import Thread
from datetime import datetime

# Global variables to store state
connected_hosts = {}
mac_lookup = MacLookup()
blocked_macs = set()
monitoring_active = False

# Load configuration from JSON file
with open('conf.json') as f:
    conf = json.load(f)
    TOKEN = conf["TOKEN"]
    CHAT_ID = conf["CHAT_ID"]
    NETWORK = conf["NETWORK"]
    INTERVAL = conf["INTERVAL"]

# Main menu layout for the Telegram bot
main_menu = ReplyKeyboardMarkup(
    [["/start", "/stop", "/showall"], ["/block", "/unblock", "/showblocked"]],
    resize_keyboard=True
)

# Returns the vendor of a MAC address
# If lookup fails, returns 'Nomaʼlum' (Unknown)
def get_mac_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except:
        return 'Nomaʼlum'

# Blocks a MAC address using iptables
# Returns True if successful, False otherwise
def block_mac_iptables(mac):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables-save'], check=True)
        return True
    except:
        return False

# Unblocks a MAC address using iptables
# Returns True if successful, False otherwise
def unblock_mac_iptables(mac):
    try:
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables-save'], check=True)
        return True
    except:
        return False

# Loads MAC addresses from file and blocks them
# Adds them to the blocked_macs set
def load_blocked_macs():
    try:
        with open('blocked_macs.txt', 'r') as f:
            for line in f:
                mac = line.strip()
                if mac and mac not in blocked_macs:
                    if block_mac_iptables(mac):
                        blocked_macs.add(mac)
    except FileNotFoundError:
        open('blocked_macs.txt', 'w').close()

# Saves current blocked MACs to a file
def save_blocked_macs():
    with open('blocked_macs.txt', 'w') as f:
        for mac in blocked_macs:
            f.write(f"{mac}\n")

# Tries to detect the appropriate network interface
def get_interface():
    try:
        route = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in route.stdout.split('\n'):
            if 'default' in line and 'wlo1' in line:
                return 'wlo1'
            elif 'default' in line and 'eth0' in line:
                return 'eth0'
        return 'wlo1'  # fallback
    except:
        return 'wlo1'  # fallback

# Performs an ARP scan to detect devices on the network
def arp_scan():
    interface = get_interface()
    devices = []
    try:
        ans, _ = arping(NETWORK, iface=interface, verbose=0, timeout=5)
        if ans:
            return [(rcv.src, rcv.psrc) for snd, rcv in ans]
    except:
        pass
    try:
        result = subprocess.run(['sudo', 'arp-scan', '-l', '-I', interface, '--localnet'], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            if re.match(r'^(([0-9]{1,3}\.){3}[0-9]{1,3}\s)', line):
                parts = line.split()
                devices.append((parts[1], parts[0]))
        return devices
    except:
        return None

# Monitors the network for new or disconnected devices
def monitor_network(context):
    global monitoring_active, connected_hosts
    while monitoring_active:
        try:
            devices = arp_scan()
            current_macs = [mac for mac, ip in devices] if devices else []

            # Notify when a new device connects
            for mac, ip in devices or []:
                if mac in blocked_macs:
                    continue
                if mac not in connected_hosts:
                    vendor = get_mac_vendor(mac)
                    connected_hosts[mac] = (vendor, ip)
                    context.bot.send_message(chat_id=CHAT_ID, text=f"🟢 Yangi qurilma ulandi:\n{vendor} ({ip} - {mac})")

            # Notify when a device disconnects
            for mac in list(connected_hosts):
                if mac not in current_macs and mac not in blocked_macs:
                    vendor, ip = connected_hosts[mac]
                    context.bot.send_message(chat_id=CHAT_ID, text=f"🔴 Qurilma uzildi:\n{vendor} ({ip} - {mac})")
                    del connected_hosts[mac]
            time.sleep(INTERVAL)
        except:
            time.sleep(5)

# Starts network monitoring
def start_command(update, context):
    global monitoring_active
    if not monitoring_active:
        monitoring_active = True
        Thread(target=monitor_network, args=(context,)).start()
        update.message.reply_text("🔍 Qurilmalar kuzatuvi boshlandi...", reply_markup=main_menu)
    else:
        update.message.reply_text("⚠️ Kuzatuv allaqachon ishlamoqda", reply_markup=main_menu)

# Stops network monitoring
def stop_command(update, context):
    global monitoring_active
    if monitoring_active:
        monitoring_active = False
        update.message.reply_text("🛑 Qurilmalar kuzatuvi to'xtatildi", reply_markup=main_menu)
    else:
        update.message.reply_text("⚠️ Kuzatuv allaqachon to'xtatilgan", reply_markup=main_menu)

# Displays all currently detected devices
def showall_command(update, context):
    devices = arp_scan()
    if not devices:
        update.message.reply_text("⚠️ Hech qanday qurilma topilmadi.", reply_markup=main_menu)
        return
    msg = f"📋 Qurilmalar ro'yxati ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n\n"
    for mac, ip in devices:
        status = "⛔️ (Bloklangan)" if mac in blocked_macs else "🟢 (Faol)"
        vendor = get_mac_vendor(mac)
        msg += f"{status} {vendor}\nIP: {ip}\nMAC: {mac}\n\n"
    update.message.reply_text(msg[:4096], reply_markup=main_menu)

# Blocks a specific MAC address from network access
def block_command(update, context):
    args = context.args
    if len(args) != 1:
        update.message.reply_text("❗ Foydalanish: /block AA:BB:CC:DD:EE:FF", reply_markup=main_menu)
        return
    mac = args[0].upper()
    if not re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac):
        update.message.reply_text("❗ Noto'g'ri MAC manzil", reply_markup=main_menu)
        return
    if mac in blocked_macs:
        update.message.reply_text("⚠️ Bu MAC allaqachon bloklangan", reply_markup=main_menu)
        return
    if block_mac_iptables(mac):
        blocked_macs.add(mac)
        save_blocked_macs()
        update.message.reply_text(f"⛔️ {mac} bloklandi", reply_markup=main_menu)
    else:
        update.message.reply_text("❌ Bloklashda xatolik", reply_markup=main_menu)

# Unblocks a previously blocked MAC address
def unblock_command(update, context):
    args = context.args
    if len(args) != 1:
        update.message.reply_text("❗ Foydalanish: /unblock AA:BB:CC:DD:EE:FF", reply_markup=main_menu)
        return
    mac = args[0].upper()
    if mac not in blocked_macs:
        update.message.reply_text("⚠️ Bu MAC bloklanmagan", reply_markup=main_menu)
        return
    if unblock_mac_iptables(mac):
        blocked_macs.remove(mac)
        save_blocked_macs()
        update.message.reply_text(f"✅ {mac} blokdan olindi", reply_markup=main_menu)
    else:
        update.message.reply_text("❌ Blokdan olishda xatolik", reply_markup=main_menu)

# Displays all currently blocked MAC addresses
def showblocked_command(update, context):
    if not blocked_macs:
        update.message.reply_text("🚫 Bloklangan MAC manzillar yo'q", reply_markup=main_menu)
        return
    msg = "🚫 Bloklangan MAC manzillar:\n\n" + '\n'.join(blocked_macs)
    update.message.reply_text(msg[:4096], reply_markup=main_menu)

# Entry point of the script
if __name__ == '__main__':
    load_blocked_macs()  # Load blocked MACs from file
    updater = Updater(token=TOKEN)
    dp = updater.dispatcher

    # Register command handlers
    dp.add_handler(CommandHandler("start", start_command))
    dp.add_handler(CommandHandler("stop", stop_command))
    dp.add_handler(CommandHandler("showall", showall_command))
    dp.add_handler(CommandHandler("block", block_command))
    dp.add_handler(CommandHandler("unblock", unblock_command))
    dp.add_handler(CommandHandler("showblocked", showblocked_command))

    updater.start_polling()  # Start polling Telegram updates
    updater.idle()  # Run until interrupted
