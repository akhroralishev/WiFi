from scapy.all import arping
from telegram.ext import Updater, CommandHandler, MessageHandler
from telegram.ext import filters
from telegram import ReplyKeyboardMarkup
from mac_vendor_lookup import MacLookup
import json
import time
import subprocess
import re
from threading import Thread
from datetime import datetime

# Global o'zgaruvchilar
connected_hosts = {}
mac_lookup = MacLookup()
blocked_macs = set()
monitoring_active = False

# Konfiguratsiya faylidan sozlamalarni o'qish
with open('conf.json') as f:
    conf = json.load(f)
    TOKEN = conf["TOKEN"]
    CHAT_ID = conf["CHAT_ID"]
    NETWORK = conf["NETWORK"]
    INTERVAL = conf["INTERVAL"]

# Reply keyboard
main_menu = ReplyKeyboardMarkup(
    [["/start", "/stop", "/showall"], 
     ["/block", "/unblock", "/showblocked"]],
    resize_keyboard=True
)

def get_mac_vendor(mac):
    try:
        vendor = mac_lookup.lookup(mac)
        return vendor
    except Exception as e:
        print(f"MAC lookup xatoligi: {e}")
        return 'Nomaʼlum'

def block_mac_iptables(mac_address):
    try:
        subprocess.run([
            'sudo', 'iptables', '-A', 'INPUT', '-m', 'mac', 
            '--mac-source', mac_address, '-j', 'DROP'
        ], check=True)
        
        subprocess.run([
            'sudo', 'iptables', '-A', 'OUTPUT', '-m', 'mac', 
            '--mac-source', mac_address, '-j', 'DROP'
        ], check=True)
        
        subprocess.run(['sudo', 'iptables-save'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Bloklashda xato: {e}")
        return False

def unblock_mac_iptables(mac_address):
    try:
        subprocess.run([
            'sudo', 'iptables', '-D', 'INPUT', '-m', 'mac', 
            '--mac-source', mac_address, '-j', 'DROP'
        ], check=True)
        
        subprocess.run([
            'sudo', 'iptables', '-D', 'OUTPUT', '-m', 'mac', 
            '--mac-source', mac_address, '-j', 'DROP'
        ], check=True)
        
        subprocess.run(['sudo', 'iptables-save'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Blokdan olishda xato: {e}")
        return False

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

def save_blocked_macs():
    with open('blocked_macs.txt', 'w') as f:
        for mac in blocked_macs:
            f.write(f"{mac}\n")

# def get_interface():
#     """Avtomatik ravishda faol tarmoq interfeysini aniqlash"""
#     try:
#         # Linux uchun ip route buyrug'i orqali
#         route = subprocess.run(['ip', 'route'], capture_output=True, text=True)
#         for line in route.stdout.split('\n'):
#             if 'default' in line:
#                 return line.split()[4]  # Interfeys nomini qaytaradi
#         return 'eth0'  # Standart Ethernet interfeysi
#     except Exception as e:
#         print(f"Interfeysni aniqlashda xato: {e}")
#         return 'eth0'
def get_interface():
    try:
        # Avtomatik aniqlash
        route = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in route.stdout.split('\n'):
            if 'default' in line and 'wlo1' in line:  # Wi-Fi uchun
                return 'wlo1'
            elif 'default' in line and 'eth0' in line:  # Ethernet uchun
                return 'eth0'
        return 'wlo1'  # Standart qiymat
    except Exception as e:
        print(f"Interfeysni aniqlashda xato: {e}")
        return 'wlo1'

def arp_scan():
    try:
        interface = get_interface()
        print(f"DEBUG: Foydalanilayotgan interfeys: {interface}")  # Debug
        
        # ARP skanerlash uchun ikkita usul
        devices = []
        
        # 1-usul: scapy orqali
        try:
            ans, _ = arping(NETWORK, iface=interface, verbose=0, timeout=5)
            if ans:
                print(f"DEBUG: Scapy orqali topilgan qurilmalar: {len(ans)}")
                return [(host[1].src, host[1].psrc) for host in ans]
        except Exception as e:
            print(f"Scapy ARP xatosi: {e}")
        
        # 2-usul: arp-scan orqali
        try:
            cmd = ['sudo', 'arp-scan', '-l', '-I', interface, '--localnet']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                if re.match(r'^(([0-9]{1,3}\.){3}[0-9]{1,3}\s)', line):
                    parts = line.split()
                    ip = parts[0]
                    mac = parts[1]
                    devices.append((mac, ip))
            
            if devices:
                print(f"DEBUG: arp-scan orqali topilgan qurilmalar: {len(devices)}")
                return devices
        except Exception as e:
            print(f"arp-scan xatosi: {e}")
        
        return None
        
    except Exception as e:
        print(f"ARP scan xatosi: {e}")
        return None

def monitor_network(context):
    global monitoring_active, connected_hosts
    
    while monitoring_active:
        try:
            devices = arp_scan()
            current_macs = [mac for mac, ip in devices] if devices else []
            
            # Yangi qurilmalarni aniqlash
            for mac, ip in devices or []:
                if mac in blocked_macs:
                    continue
                    
                if mac not in connected_hosts:
                    mac_vendor = get_mac_vendor(mac)
                    connected_hosts[mac] = (mac_vendor, ip)
                    msg = f"🟢 Yangi qurilma ulandi:\n{mac_vendor} ({ip} - {mac})"
                    context.bot.send_message(chat_id=CHAT_ID, text=msg)
            
            # Uzilgan qurilmalarni aniqlash
            for mac in list(connected_hosts.keys()):
                if mac not in current_macs and mac not in blocked_macs:
                    mac_vendor, ip = connected_hosts[mac]
                    msg = f"🔴 Qurilma uzildi:\n{mac_vendor} ({ip} - {mac})"
                    context.bot.send_message(chat_id=CHAT_ID, text=msg)
                    del connected_hosts[mac]
            
            time.sleep(INTERVAL)
            
        except Exception as e:
            print(f"Monitoringda xato: {e}")
            time.sleep(5)

def start_command(update, context):
    global monitoring_active
    
    if not monitoring_active:
        monitoring_active = True
        Thread(target=monitor_network, args=(context,)).start()
        update.message.reply_text(
            "🔍 Qurilmalar kuzatuvi boshlandi...", 
            reply_markup=main_menu
        )
    else:
        update.message.reply_text(
            "⚠️ Kuzatuv allaqachon ishlamoqda", 
            reply_markup=main_menu
        )

def stop_command(update, context):
    global monitoring_active
    
    if monitoring_active:
        monitoring_active = False
        update.message.reply_text(
            "🛑 Qurilmalar kuzatuvi to'xtatildi", 
            reply_markup=main_menu
        )
    else:
        update.message.reply_text(
            "⚠️ Kuzatuv allaqachon to'xtatilgan", 
            reply_markup=main_menu
        )

def showall_command(update, context):
    try:
        update.message.reply_text("🔍 Qurilmalar skanerlanyapti...", reply_markup=main_menu)
        
        devices = arp_scan()
        print(f"DEBUG: Skanerlash natijasi: {devices}")
        
        if not devices:
            update.message.reply_text(
                "⚠️ Hech qanday qurilma topilmadi. Tarmoqni tekshiring.",
                reply_markup=main_menu
            )
            return

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"📋 Tarmoq qurilmalari ({scan_time})\n\n"
        msg += f"🔍 Jami qurilmalar: {len(devices)}\n\n"
        
        for mac, ip in devices:
            status = "⛔️ (Bloklangan)" if mac in blocked_macs else "🟢 (Faol)"
            vendor = get_mac_vendor(mac)
            msg += f"{status} {vendor}\nIP: {ip}\nMAC: {mac}\n\n"
        
        # Xabar uzunligi chegarasini hisobga olish
        if len(msg) > 4096:  # Telegram xabar chegarasi
            msg = msg[:4000] + "\n\n...va yana {} qurilma".format(len(devices) - len(msg.split("\n\n")) + 1)
        
        update.message.reply_text(msg, reply_markup=main_menu)
    
    except Exception as e:
        print(f"/showall xatosi: {e}")
        update.message.reply_text(
            "❌ Qurilmalar ro'yxatini olishda xato. Loglarni tekshiring.",
            reply_markup=main_menu
        )

def block_command(update, context):
    args = context.args
    if len(args) != 1:
        update.message.reply_text(
            "❗ Foydalanish: /block AA:BB:CC:DD:EE:FF",
            reply_markup=main_menu
        )
        return

    mac_to_block = args[0].upper()
    
    if not re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac_to_block):
        update.message.reply_text(
            "❗ Noto'g'ri MAC manzil formati",
            reply_markup=main_menu
        )
        return

    if mac_to_block in blocked_macs:
        update.message.reply_text(
            "⚠️ Bu qurilma allaqachon bloklangan",
            reply_markup=main_menu
        )
        return

    if block_mac_iptables(mac_to_block):
        blocked_macs.add(mac_to_block)
        save_blocked_macs()
        
        if mac_to_block in connected_hosts:
            vendor, ip = connected_hosts[mac_to_block]
            msg = f"⛔️ Qurilma bloklandi:\n{vendor} ({ip} - {mac_to_block})"
        else:
            msg = f"⛔️ MAC manzil bloklandi: {mac_to_block}"
    else:
        msg = "❌ Bloklash amalga oshirilmadi. Administrator bilan bog'laning."

    update.message.reply_text(msg, reply_markup=main_menu)

def unblock_command(update, context):
    args = context.args
    if len(args) != 1:
        update.message.reply_text(
            "❗ Foydalanish: /unblock AA:BB:CC:DD:EE:FF",
            reply_markup=main_menu
        )
        return

    mac_to_unblock = args[0].upper()
    
    if mac_to_unblock not in blocked_macs:
        update.message.reply_text(
            "⚠️ Bu qurilma bloklanmagan",
            reply_markup=main_menu
        )
        return

    if unblock_mac_iptables(mac_to_unblock):
        blocked_macs.discard(mac_to_unblock)
        save_blocked_macs()
        msg = f"✅ {mac_to_unblock} blokdan olindi"
    else:
        msg = "❌ Blokdan olish amalga oshirilmadi. Administrator bilan bog'laning."

    update.message.reply_text(msg, reply_markup=main_menu)

def showblocked_command(update, context):
    if not blocked_macs:
        update.message.reply_text(
            "ℹ️ Bloklangan qurilmalar mavjud emas",
            reply_markup=main_menu
        )
        return
    
    msg = "⛔️ Bloklangan qurilmalar ro'yxati:\n\n"
    for mac in blocked_macs:
        if mac in connected_hosts:
            vendor, ip = connected_hosts[mac]
            msg += f"- {vendor}\nIP: {ip}\nMAC: {mac}\n\n"
        else:
            msg += f"- MAC: {mac} (hozir tarmoqda emas)\n\n"
    
    update.message.reply_text(msg, reply_markup=main_menu)

def error_handler(update, context):
    print(f"❗️ Xatolik: {context.error}")
    if update and update.message:
        update.message.reply_text(
            "❌ Xato yuz berdi. Iltimos, qayta urunib ko'ring.",
            reply_markup=main_menu
        )

def main():
    try:
        # MAC vendor ma'lumotlarini yangilash
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"MAC vendor ma'lumotlarini yangilashda xato: {e}")
        
        # Bloklangan MAC manzillarni yuklash
        load_blocked_macs()
        
        # Botni ishga tushirish
        updater = Updater(TOKEN, use_context=True)
        dp = updater.dispatcher

        # Command handlerlar
        dp.add_handler(CommandHandler("start", start_command))
        dp.add_handler(CommandHandler("stop", stop_command))
        dp.add_handler(CommandHandler("showall", showall_command))
        dp.add_handler(CommandHandler("block", block_command))
        dp.add_handler(CommandHandler("unblock", unblock_command))
        dp.add_handler(CommandHandler("showblocked", showblocked_command))
        
        # Xato handler
        dp.add_error_handler(error_handler)

        print("[+] BOT ishga tushdi")
        updater.start_polling()
        updater.idle()
        
    except Exception as e:
        print(f"Botni ishga tushirishda xato: {e}")

if __name__ == "__main__":
    main()
