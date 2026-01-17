# 2IC80-Project - SPOOFY: ARP Poisoning & DNS Spoofing with SSL Stripping tool

## Table of Contents
* [Overview](#overview)
* [Features](#features)
* [Attack Modes](#attack-modes)
* [Kathara Lab Environment](#kathara-lab-environment)
* [Instruction Guide](#instruction-guide)

## Overview 
This project implements a **fully-fledged, plug-and-play Man-in-the-Middle (MITM)** attack toolkit using **Python and Scapy**.  
The tool performs automated interception and manipulation of traffic through a combination of:

- **ARP Poisoning**
- **DNS Spoofing**
- **SSL Stripping**

## Features
### 1. ARP Poisoning
- Performs **ARP cache poisoning** between victim and gateway  
- Intercepts and relays packets while keeping the victim online 
- Includes a **silent mode** that minimizes ARP traffic to reduce detection footprint  

### 2. DNS Spoofing Engine
- Intercepts DNS queries passing through the attacker  
- Injects forged DNS responses before the legitimate resolver  
- Supports per-domain redirection (e.g., `example.com → attacker IP`)  
- Integrates seamlessly when paired with the ARP MITM position  

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
Each attack technique is implemented as a separate module within `/home/lab/src/`, enabling easy maintenance and future extensions.

## Attack Modes
- **arp-only** - Performs two directional ARP poisoning to position the attacker as MINT between the victim and the gateway.
    - **all-out** mode - Continuous (gratuitous) poisoning at set intervals. This is the default mode.
    - **silent** mode - Reactive posoning based on sniffed ARP traffic.
- **dns-only** - Stealthy DNS redirection without persistent MITM.
- **arp-dns** - Guaranteed DNS redirection for targeted domains. Combines ARP poisoning with DNS spoofing.
- **arp-ssl** - Downgrading and intercepting encrypted web traffic. Uses ARP poisoning to establish MITM position and then leverages by the SSL stripper.
- **arp-dns-ssl** - Provides full control over victim's traffic. ARP poisoning makes traffic go through the attacker, DNS spoofing provides control over where the victim connects, and SSL stripping is applied to mediate encrypted web traffic.

## Kathara Lab Environment
A **Kathara network lab** was made to test the attacks in an isolated environment.

The lab includes:

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

## Instruction Guide

### Prerequisites
Ensure the following are installed on your host machine:

- **Kathara** (3.8.0 version)
- **Docker**
- **Python 3** on the host (for editing the toolkit)

### 1. Starting the lab
Navigate to `lab/` and launch:
```bash
cd ./lab
kathara lstart
```

### 2. Running the tool
Inside the Attacker Terminal:

```bash
cd /home/lab/
source venv/bin/activate
cd src/
python console.py
```
<img src="image.png" width="40%">

Alternatively, the attack can be run using:
```
python main.py run ...
```

Where the remainder of the command consists of parameters passed to the attack.

### 3. Interrupting/Stopping the attack:
The attacks can be stopped from the command line using Ctrl+C

### 4. Stopping the lab
From the host machine to cleanly remove all VMs and close Kathara run:
```bash
cd lab/
kathara lclean
```


