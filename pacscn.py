import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP
import threading
import matplotlib.pyplot as plt
from collections import defaultdict

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x500")
        self.root.resizable(False, False)

        # UI Elements
        self.label = tk.Label(root, text="Network Packet Analyzer", font=("Arial", 14, "bold"))
        self.label.pack(pady=5)

        self.protocol_label = tk.Label(root, text="Filter by Protocol:")
        self.protocol_label.pack()

        self.protocol_var = tk.StringVar()
        self.protocol_var.set("All")
        self.protocol_menu = ttk.Combobox(root, textvariable=self.protocol_var, values=["All", "TCP", "UDP"])
        self.protocol_menu.pack(pady=5)

        self.text_area = scrolledtext.ScrolledText(root, width=90, height=15)
        self.text_area.pack(pady=5)

        self.start_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=20, pady=10)

        self.stop_button = ttk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=20, pady=10)

        self.graph_button = ttk.Button(root, text="Show Graph", command=self.show_graph)
        self.graph_button.pack(side=tk.LEFT, padx=20, pady=10)

        # Sniffing Control
        self.sniffing = False
        self.sniff_thread = None
        self.packet_counts = defaultdict(int)

    def start_sniffing(self):
        """Starts the packet sniffing process in a separate thread."""
        self.sniffing = True
        self.text_area.insert(tk.END, "Starting packet sniffing...\n")
        self.text_area.yview(tk.END)

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Running sniffing in a separate thread to keep UI responsive
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        """Stops the packet sniffing process."""
        self.sniffing = False
        self.text_area.insert(tk.END, "Stopped packet sniffing.\n")
        self.text_area.yview(tk.END)

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        """Captures network packets based on user-selected protocol."""
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=False)

    def process_packet(self, packet):
        """Processes captured packets and displays relevant information based on filter."""
        if not self.sniffing:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "OTHER"

            if TCP in packet:
                protocol = "TCP"
                details = f"Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
            elif UDP in packet:
                protocol = "UDP"
                details = f"Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
            else:
                details = "No Port Info"

            # Check if the selected protocol matches
            selected_protocol = self.protocol_var.get()
            if selected_protocol != "All" and protocol != selected_protocol:
                return

            # Update packet count for visualization
            self.packet_counts[protocol] += 1

            log = f"Source: {src_ip} → Destination: {dst_ip} | Protocol: {protocol} | {details}\n"
            self.text_area.insert(tk.END, log)
            self.text_area.yview(tk.END)

    def show_graph(self):
        """Displays a bar chart showing the count of each protocol captured."""
        plt.figure(figsize=(6, 4))
        plt.bar(self.packet_counts.keys(), self.packet_counts.values(), color=['blue', 'red', 'green'])
        plt.xlabel("Protocol")
        plt.ylabel("Packet Count")
        plt.title("Network Packet Distribution")
        plt.show()

# Run the GUI Application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
