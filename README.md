# Scooby

This script automates network scanning using [Nmap](https://nmap.org/), [autosslscan](https://github.com/BeeSec-UK/autosslscan), and [http-get](scripts/http_get_improved.py). It uses all of these tools and formats the results in a comprehensive way.

## Usage
Assuming Nmap is on your system, and all [requirements](requirements.txt) are installed:
1. Define the target CIDR ranges in your target file, for example: `echo "192.168.1.0/24 : home_network" > targets.txt`<br>

Make sure `targets.txt` is in the same directory as `main.py` and is in the format `CIDR_RANGE : CUSTOM_NAME`
2. Run the script:
<br>`python main.py`
