from scapy.all import sniff, IP, UDP, DNS, BOOTP, DHCP
from scapy.utils import wrpcap
from scapy.layers.dns import DNSQR
from datetime import datetime
from rich.live import Live
from rich.table import Table
from collections import defaultdict, Counter
import csv

# Store captured packets
captured_packets = []

# Stats counters
stats = {
    "total": 0,
    "dns": 0,
    "dhcp": 0,
    "other_udp": 0
}

# For top talkers and byte tracking
ip_counter = Counter()
byte_tracker = defaultdict(int)

# CSV logging setup
with open("packet_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Bytes"])

# Packet handler
def packet_callback(packet):
    if IP in packet and UDP in packet:
        stats["total"] += 1
        captured_packets.append(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        timestamp = datetime.now().strftime("%H:%M:%S")
        length = len(packet)

        # Update talkers and byte stats
        ip_counter[src_ip] += 1
        byte_tracker[src_ip] += length

        # Detect protocol
        protocol = "Other UDP"
        if packet.haslayer(DNS):
            protocol = "DNS"
            stats["dns"] += 1
        elif packet.haslayer(DHCP):
            protocol = "DHCP"
            stats["dhcp"] += 1
        else:
            stats["other_udp"] += 1

        # Log to terminal
        log_line = f"[{timestamp}] [{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {length} bytes"
        print(log_line)

        # Log to CSV
        with open("packet_log.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, protocol, src_ip, src_port, dst_ip, dst_port, length])

# Real-time dashboard
def render_dashboard():
    table = Table(title="Live Packet Sniffer Stats")

    table.add_column("Metric", style="bold cyan")
    table.add_column("Count", justify="right", style="bold yellow")

    table.add_row("Total UDP Packets", str(stats["total"]))
    table.add_row("DNS Packets", str(stats["dns"]))
    table.add_row("DHCP Packets", str(stats["dhcp"]))
    table.add_row("Other UDP", str(stats["other_udp"]))
    table.add_row("---", "---")
    table.add_row("Top Talkers", "")

    for ip, count in ip_counter.most_common(5):
        table.add_row(f"{ip}", f"{count} pkts / {byte_tracker[ip]} bytes")

    return table

# Main sniffer function
def main():
    print("Starting advanced packet sniffer (UDP)... Press CTRL+C to stop.\n")

    with Live(render_dashboard(), refresh_per_second=1) as live:
        try:
            sniff(filter="udp", prn=lambda p: (packet_callback(p), live.update(render_dashboard())))
        except KeyboardInterrupt:
            print("\n\nStopping capture. Saving packets...")

    wrpcap("advanced_udp_capture.pcap", captured_packets)
    print("Saved to advanced_udp_capture.pcap and packet_log.csv")

if __name__ == "__main__":
    main()
