# 2IC80-Project - ARP Poisoning & DNS Spoofing Tool with SSL Stripping tool

This project implements a **fully-fledged, plug-and-play Man-in-the-Middle (MITM)** attack toolkit using **Python and Scapy**.  
The tool performs automated interception and manipulation of traffic through a combination of:

- **ARP Poisoning**
- **DNS Spoofing**
- **SSL Stripping**

## Features

### 1. ARP Poisoning
- Performs **ARP cache poisoning** between victim and gateway  
- Intercepts and relays packets while keeping the victim online 
- Includes a **stealth mode** that minimizes ARP traffic to reduce detection footprint  

### 2. DNS Spoofing Engine
- Intercepts DNS queries passing through the attacker  
- Injects forged DNS responses before the legitimate resolver  
- Supports per-domain redirection (e.g., `example.com → attacker IP`)  
- Integrates seamlessly with the ARP MITM position  

### 3. SSL Stripping
- Downgrades HTTPS connections to HTTP when possible  
- Removes HTTPS redirections and rewrites responses
- Operates transparently once MITM is established  

### 4. Automation
The toolkit automatically adapts to new networks by performing:

- Discovery of attacker IP, MAC, and active interface  
- Automatic detection of the default gateway  
- Scanning and enumeration of potential victims  
- Detection of DNS servers used by the victim  
- Automatic enabling of packet forwarding  

This allows the tool to run with minimal user configuration.

### 6. Modular Architecture
Each attack technique is implemented as a separate module within `home/lab/src/`, enabling easy maintenance and future extensions.


## Kathara Lab Environment
A **Kathara network lab** was made to test the attacks in an isolated environment.

The lab (for now) includes:

- **Attacker node** running the MITM toolkit  
- **Victim node** to demonstrate ARP, DNS, and SSL manipulation
- **Server node** running a http website on port 80
- **Gateway node** running DNS server on port 53
- All connected on the same subnetwork

Startup scripts automatically configure:
- IP addressing  
- Routing
- DNS
- Python environment on the attacker VM with the tools from /src directory
- Changes to the code from the host update dynamically in the attacker

## Running the Kathara Lab
Ensure the following are installed on your host machine:

- **Kathara** (3.8.0 version)
- **Docker**
- **Python 3** on the host (for editing the toolkit)

### Starting the lab
Navigate into the `lab/` directory and launch:
```bash
cd /lab
kathara lstart
```

### Running the tool
Inside the attacker VM:

```bash
cd /home/lab/src
python3 main.py --victim-ip 10.0.0.20 --target-ip 10.0.0.30 -i eth0
```

### Stopping the lab
From the host machine to cleanly remove all VMs and close Kathara run:
```bash
cd lab/
kathara lclean
```


