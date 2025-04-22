import tkinter as tk  
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from scapy.all import sniff, IP, UDP, TCP, ARP, ICMP, DNS
from threading import Thread
from datetime import datetime
from collections import Counter
from tkinter import messagebox
import csv
import geoip2.database


# GeoIP lookup


def get_geo_info(ip):
    try:
        with geoip2.database.Reader("GeoLite2-City.mmdb") as reader:
            response = reader.city(ip)
            country = response.country.name or "Unknown"
            return country
    except:
        return "N/A"

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.sniffing = False
        self.sniff_thread = None
        self.ip_filter = ""
        self.ip_counter = Counter()
        self.protocol_filters = {"UDP": tk.BooleanVar(value=True),
                                 "TCP": tk.BooleanVar(value=False),
                                 "DNS": tk.BooleanVar(value=False),
                                 "ARP": tk.BooleanVar(value=False),
                                 "ICMP": tk.BooleanVar(value=False)}

        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        style = self.root.style
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 10))
        style.configure("TLabelFrame.Label", font=("Segoe UI", 11, "bold"))

    def setup_ui(self):
        self.root.columnconfigure(0, weight=1)

        header = ttk.Label(self.root, text="Network Packet Sniffer", font=("Segoe UI", 22, "bold"), bootstyle="primary-inverse")
        header.grid(row=0, column=0, pady=(10, 5), padx=20, sticky="ew")

        controls = ttk.Frame(self.root, padding=10)
        controls.grid(row=1, column=0, sticky="ew", padx=20)
        controls.columnconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        self.start_btn = ttk.Button(controls, text="\u25B6 Start", bootstyle="success", command=self.start_sniffing)
        self.start_btn.grid(row=0, column=0, padx=5, pady=5)

        self.stop_btn = ttk.Button(controls, text="\u25A0 Stop", bootstyle="danger", command=self.stop_sniffing, state=DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=5)

        self.export_btn = ttk.Button(controls, text="\U0001F4BE Export CSV", bootstyle="secondary", command=self.export_csv)
        self.export_btn.grid(row=0, column=2, padx=5)

        ttk.Label(controls, text="IP Filter:").grid(row=0, column=3, padx=5)
        self.ip_entry = ttk.Entry(controls, width=15)
        self.ip_entry.grid(row=0, column=4, padx=5)

        self.theme_combo = ttk.Combobox(controls, values=self.root.style.theme_names(), width=10)
        self.theme_combo.set(self.root.style.theme_use())
        self.theme_combo.bind("<<ComboboxSelected>>", self.change_theme)
        self.theme_combo.grid(row=0, column=5, padx=5)

        proto_frame = ttk.Frame(self.root, padding=(15, 0))
        proto_frame.grid(row=2, column=0, sticky="w")
        for i, proto in enumerate(self.protocol_filters):
            cb = ttk.Checkbutton(proto_frame, text=proto, variable=self.protocol_filters[proto])
            cb.grid(row=0, column=i, padx=5)

        log_frame = ttk.Labelframe(self.root, text="Captured Packets", padding=15, bootstyle="info")
        log_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        self.root.rowconfigure(3, weight=1)

        columns = ("time", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "bytes", "geo")
        self.tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=25, bootstyle="info")
        headings = ["Time", "Proto", "Source IP", "Src Port", "Destination IP", "Dst Port", "Bytes", "GeoIP"]
        widths = [80, 60, 130, 70, 130, 70, 60, 120]
        for col, head, width in zip(columns, headings, widths):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width, anchor="center")

        # Protocol color tags
        self.tree.tag_configure("DNS", background="#004080")
        self.tree.tag_configure("UDP", background="#1a1a1a")
        self.tree.tag_configure("TCP", background="#660000")
        self.tree.tag_configure("ARP", background="#004d00")
        self.tree.tag_configure("ICMP", background="#cc5200")

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def start_sniffing(self):
        if self.sniffing:
            return
        self.sniffing = True
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.ip_filter = self.ip_entry.get().strip()
        self.tree.delete(*self.tree.get_children())

        self.sniff_thread = Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

        with open("sniff_log.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Protocol", "Src IP", "Src Port", "Dst IP", "Dst Port", "Size", "GeoIP"])

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)

    def export_csv(self):
        messagebox.showinfo("Exported", "Saved as sniff_log.csv")

    def change_theme(self, event):
        theme = self.theme_combo.get()
        self.root.style.theme_use(theme)

    def sniff_packets(self):
        sniff(filter="ip", prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, packet):
        proto = None
        if packet.haslayer(DNS):
            proto = "DNS"
        elif packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ARP):
            proto = "ARP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        if not proto or not self.protocol_filters[proto].get():
            return

        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        src_port = packet[TCP].sport if proto == "TCP" else packet[UDP].sport if proto == "UDP" else ""
        dst_port = packet[TCP].dport if proto == "TCP" else packet[UDP].dport if proto == "UDP" else ""
        size = len(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")
        geo = get_geo_info(src_ip)

        if self.ip_filter and self.ip_filter not in (src_ip, dst_ip):
            return

        self.tree.insert("", "end", values=(timestamp, proto, src_ip, src_port, dst_ip, dst_port, size, geo), tags=(proto,))
        self.tree.yview_moveto(1.0)  # Auto-scroll

        with open("sniff_log.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, proto, src_ip, src_port, dst_ip, dst_port, size, geo])

if __name__ == "__main__":
    app = ttk.Window(themename="darkly", title="Network Packet Sniffer", size=(1100, 720))
    gui = PacketSnifferGUI(app)
    app.mainloop()
