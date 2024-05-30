import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        self.master.title("Packet Sniffer Tool")

        # Create Start and Stop buttons
        self.start_button = ttk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = ttk.Button(master, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        # Create the Treeview to display packets
        self.tree = ttk.Treeview(master, columns=('Source', 'Destination', 'Protocol', 'Info'), show='headings')
        self.tree.heading('Source', text='Source')
        self.tree.heading('Destination', text='Destination')
        self.tree.heading('Protocol', text='Protocol')
        self.tree.heading('Info', text='Info')

        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Initialize sniffer variables
        self.sniffing = False
        self.sniffer_thread = None

    def start_sniffing(self):
        self.sniffing = True
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            if TCP in packet:
                proto_name = "TCP"
                info = f"Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
            elif UDP in packet:
                proto_name = "UDP"
                info = f"Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
            else:
                proto_name = "Other"
                info = ""

            # Insert packet information into the treeview
            self.tree.insert('', tk.END, values=(ip_src, ip_dst, proto_name, info))

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
