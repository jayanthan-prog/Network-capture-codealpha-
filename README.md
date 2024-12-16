# Network-capture-codealpha-
This repo contains the python program to capture the network sharing and the packets


TASK 1

BASIC NETWORK SNIFFER

Build a network sniffer in Python that
captures and analyzes network traffic. This
project will help you understand how data
flows on a network and how network packets
are structured.

OS USED:ARCH LINUX

Solution:
 INSTALLING THE REQUIRED PACKAGES FOR THE SYSTEM(sudo pacman -S python python-pip  





1. Update Your System
Update your Arch Linux system to ensure you have the latest software versions.

sudo pacman -Syu



2. Install Python and Required Tools
Ensure you have Python installed. You will also need pip for managing Python packages.
sudo pacman -S python python-pip



3. Install Required Python Packages
For packet sniffing, you can use the scapy library, which is a powerful tool for packet manipulation and analysis.
pip install scapy


You may also need additional libraries depending on your script's functionality:
netifaces: To work with network interfaces.
pandas: For traffic analysis or exporting to files.
Install these libraries if required:

pip install netifaces pandas



4. Enable Packet Capturing Capabilities
On Linux, packet capturing requires root permissions. You can run the Python script with sudo or set the necessary capabilities to allow your script to capture packets without root.
Grant cap_net_raw capability to Python:
sudo setcap cap_net_raw+eip $(which python3)


5. Write the Python Script
Below is a basic network sniffer script using scapy:

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
        if TCP in packet:
            print(f"  TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Packet: {packet[UDP].sport} -> {packet[UDP].dport}")

# Start sniffing on the desired interface (replace 'eth0' with your network interface)
print("Starting the packet sniffer...")
sniff(iface="eth0", prn=packet_callback, store=False)

Save this script as network_sniffer.py.

6. Run the Script
Run the script with root privileges or after setting cap_net_raw.

sudo python3 network_sniffer.py


7. Identify Your Network Interface
To find the name of your network interface (e.g., eth0, wlan0), use:
ip link show

Replace eth0 in the script with your actual interface name.

    

