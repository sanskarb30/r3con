R3CON Tool by Sanskar Bhobaskar is a Python command-line recon utility. It offers HTTP recon, subdomain/directory bruteforce (custom wordlists), flexible port scanning, banner grabbing, robots.txt analysis, DNS lookup, service version scan, and OS inference. Results are logged to a `results/` folder. For ethical use on Linux.

Installation:

git clone https://github.com/sanskarb30/r3con.git

cd r3con

sudo apt update

sudo apt install -y dos2unix

dos2unix *.sh

chmod +x install.sh

./install.sh

source venv/bin/activate

python3 secbreach.py <target>


Hown this tool works:
The R3CON Tool operates by employing various network and web-based reconnaissance techniques through its modular design. It leverages Python's `requests` library for HTTP-based tasks like fetching headers, bruteforcing directories, and checking `robots.txt` by sending web requests and analyzing responses. For network-level operations such as port scanning and banner grabbing, it utilizes Python's `socket` library to establish direct TCP connections to target ports, inferring service presence and versions from the initial data received. DNS lookups are also performed using `socket` to resolve hostnames to IP addresses and identify CNAME records. All collected information is then logged to a local file for persistent record-keeping.
