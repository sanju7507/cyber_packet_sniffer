from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv

packet_count=0
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "Remote Desktop (RDP)",
    4444: "Metasploit Listener"
}

with open("packets.csv","w",newline="") as file:
    writer=csv.writer(file)
    writer.writerow([
        "Time",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Port"
    ])

def packets(packet):

    global packet_count

    if packet.haslayer(IP):
        packet_count+=1
        current_time=datetime.now().strftime("%H:%M:%S")
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        protocol="Other"
        port="N/A"

        if packet.haslayer(TCP):
            protocol="TCP"
            port=packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        print("\n" + "-" * 30)
        print(f"Packet Number : {packet_count}")
        print(f"Time          : {current_time}")
        print(f"Source IP     : {src_ip}")
        print(f"Destination   : {dst_ip}")
        print(f"Protocol      : {protocol}")
        print(f"Port          : {port}")

        if isinstance(port, int) and port in SUSPICIOUS_PORTS:
            print(f"ALERT: Suspicious Port Detected! ({SUSPICIOUS_PORTS[port]})")

        with open("packets.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                current_time,
                src_ip,
                dst_ip,
                protocol,
                port
            ])

print("Starting Cyber packet sniffer...")
print("Logging packets to packets.csv")

sniff(prn=packets, store=False)