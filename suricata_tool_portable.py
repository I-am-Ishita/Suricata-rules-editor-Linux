#!/usr/bin/env python3
print("This is suricata_tool_portable.py being executed")

import json
import os
import shutil
import subprocess

# -------------------- Paths --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # script folder
DEFAULT_RULES_DIR = os.path.join(BASE_DIR, "rules")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")

# Ensure rules folder exists
if not os.path.exists(DEFAULT_RULES_DIR):
    os.makedirs(DEFAULT_RULES_DIR, exist_ok=True)

# -------------------- Detect defaults --------------------
DEFAULT_SURICATA_PATH = shutil.which("suricata") or "/usr/bin/suricata"
DEFAULT_CONFIG_PATH = "/etc/suricata/suricata.yaml"
DEFAULT_DOWNLOADED_RULES_PATH = "/etc/suricata/rules"

# -------------------- ET rules --------------------
ET_RULES = [
    "emerging-attack_response.rules", "emerging-adware_pup.rules", "emerging-activex.rules",
    "emerging-chat.rules", "emerging-coinminer.rules", "emerging-current_events.rules",
    "emerging-deleted.rules", "emerging-dns.rules", "emerging-dos.rules", "emerging-exploit.rules",
    "emerging-exploit_kit.rules", "emerging-ftp.rules", "emerging-games.rules", "emerging-hunting.rules",
    "emerging-icmp.rules", "emerging-icmp_info.rules", "emerging-imap.rules", "emerging-inappropriate.rules",
    "emerging-info.rules", "emerging-ja3.rules", "emerging-malware.rules", "emerging-misc.rules",
    "emerging-mobile_malware.rules", "emerging-netbios.rules", "emerging-p2p.rules", "emerging-phishing.rules",
    "emerging-policy.rules", "emerging-pop3.rules", "emerging-rpc.rules", "emerging-scan.rules",
    "emerging-shellcode.rules", "emerging-smtp.rules", "emerging-snmp.rules", "emerging-sql.rules",
    "emerging-telnet.rules", "emerging-tftp.rules", "emerging-user_agents.rules", "emerging-voip.rules",
    "emerging-web_client.rules", "emerging-web_server.rules", "emerging-web_specific_apps.rules",
    "emerging-worm.rules"
]

# -------------------- Settings Functions --------------------
def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        default_settings = {
            "suricata_path": DEFAULT_SURICATA_PATH,
            "config_path": DEFAULT_CONFIG_PATH,
            "rules_folder": DEFAULT_RULES_DIR,
            "interface": "",
            "downloaded_rules_path": DEFAULT_DOWNLOADED_RULES_PATH
        }
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(default_settings, f, indent=4)
        print("Default settings.json created. You can update paths via the script.")
        return default_settings
    with open(SETTINGS_FILE, 'r') as f:
        return json.load(f)

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)
    print("Settings saved successfully!")

# -------------------- Rule Functions --------------------
def edit_rule_file(filepath):
    if not os.path.exists(filepath):
        print(f"Rule file not found. Creating new: {filepath}")
        open(filepath, 'w').close()
    with open(filepath, 'r') as f:
        lines = f.readlines()
    print("\n--- Current Rules (first 20 lines) ---")
    for i, line in enumerate(lines[:20], 1):
        print(f"{i}: {line.strip()}")
    choice = input("\nEdit line or append new? (edit/append/skip): ").strip().lower()
    if choice == "edit":
        line_no = int(input("Line number to edit: ").strip())
        if 1 <= line_no <= len(lines):
            new_text = input("New text: ")
            lines[line_no-1] = new_text + "\n"
            with open(filepath, 'w') as f:
                f.writelines(lines)
            print("Line updated!")
    elif choice == "append":
        new_rule = input("Enter new rule: ").strip()
        if new_rule:
            with open(filepath, 'a') as f:
                f.write(new_rule + "\n")
            print("Rule appended!")

def select_rule_to_edit(settings):
    # Ensure custom.rules exists
    custom_rule_path = os.path.join(settings["rules_folder"], "custom.rules")
    if not os.path.exists(custom_rule_path):
        open(custom_rule_path, 'w').close()

    print("\nWhich rules do you want to edit?")
    print("1. ET rules")
    print("2. custom.rules")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        rules = ET_RULES
    elif choice == "2":
        rules = ["custom.rules"]
    else:
        print("Invalid choice")
        return

    print("\nAvailable files:")
    for idx, file in enumerate(rules, 1):
        print(f"{idx}. {file}")
    file_choice = int(input("Enter file number to edit: ").strip()) - 1
    if not (0 <= file_choice < len(rules)):
        print("Invalid choice")
        return

    selected_file = os.path.join(settings["rules_folder"], rules[file_choice])
    edit_rule_file(selected_file)

# -------------------- Interface Functions --------------------
def update_interface(settings):
    original_interface = settings.get("interface", "")
    print("Current network interface:", original_interface)
    new_interface = input("Enter new interface (or leave blank): ").strip()
    if new_interface:
        settings['interface'] = new_interface
        save_settings(settings)
        print("Interface updated!")
        restore = input("Do you want to restore original interface? (yes/no): ").strip()
        if restore.lower() == "yes":
            settings['interface'] = original_interface
            save_settings(settings)
            print("Interface restored to original!")

# -------------------- Suricata Runner --------------------
def run_suricata(settings):
    suricata_path = settings.get("suricata_path", DEFAULT_SURICATA_PATH)
    config_path = settings.get("config_path", DEFAULT_CONFIG_PATH)
    interface = settings.get("interface", "")
    if not interface:
        print("Network interface not set. Skipping Suricata start.")
        return
    print(f"Starting Suricata on interface {interface}...")
    try:
        subprocess.Popen([suricata_path, "-c", config_path, "-i", interface])
        print("Suricata started successfully.")
    except Exception as e:
        print("Error starting Suricata:", e)

# -------------------- Main --------------------
def main():
    settings = load_settings()

    downloaded_path = input("Enter path where ET/protocol rules are downloaded (or leave blank): ").strip()
    if downloaded_path:
        settings['downloaded_rules_path'] = downloaded_path

    suricata_path = input("Suricata path (or leave blank): ").strip()
    if suricata_path:
        settings['suricata_path'] = suricata_path

    config_path = input("Config path (or leave blank): ").strip()
    if config_path:
        settings['config_path'] = config_path

    rules_folder = input("Rules folder (or leave blank): ").strip()
    if rules_folder:
        settings['rules_folder'] = rules_folder

    save_settings(settings)

    edit_choice = input("\nEdit rules? (yes/no): ").strip().lower()
    if edit_choice == "yes":
        select_rule_to_edit(settings)

    update_choice = input("\nUpdate network interface? (yes/no): ").strip().lower()
    if update_choice == "yes":
        update_interface(settings)

    run_choice = input("\nDo you want to start Suricata now? (yes/no): ").strip().lower()
    if run_choice == "yes":
        run_suricata(settings)

    print("\nConfiguration complete!")

# -------------------- Execute --------------------
if __name__ == "__main__":
    main()
