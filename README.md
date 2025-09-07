# Suricata-rules-editor-Linux
A Linux Python tool to edit, add, and manage Suricata rules easily.

Note: The script can still be used to edit rules and configure settings even if Suricata is not installed.

Prerequisites:
1. Linux with Python 3
2. Suricata is optional; only needed to actually run it.

Setup:
1. Clone the repository.
2. The rules/ folder is included in the repo, with ET rules and custom.rules ready to use or edit.

Run:
1. Launch the script.
2. Enter paths or leave blank for defaults, or edit settings.json directly to set default paths and interface (preferred).
3. Edit ET or custom rules.
4. Update the network interface. (Optional)
5. Start Suricata if installed.

Notes:
1. custom.rules can be empty.
2. settings.json is created automatically by the script and should not be committed.
