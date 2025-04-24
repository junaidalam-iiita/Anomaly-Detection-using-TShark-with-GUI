'''import subprocess
import pandas as pd
import pickle
import threading
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from collections import Counter
import numpy as np

# Load trained model
with open("trained_model.pkl", "rb") as f:
    model = pickle.load(f)

# Default interface and packet count (will be set by user selection)
interface_name = None
packet_count = 10000

fields = [
    "_ws.col.No.", "frame.time_epoch", "ip.src", "ip.dst", "frame.len",
    "_ws.col.Protocol", "tcp.srcport", "tcp.dstport", "tcp.flags",
    "ip.ttl", "tcp.window_size_value"
]

# Attack type mapping (adjust based on your model's classes)
ATTACK_TYPES = {
    0: "Normal",
    1: "DoS",
    2: "Probe",
    3: "R2L",
    4: "U2R"
}

# Color schemes for consistent visualization
COLOR_SCHEMES = {
    "normal_vs_malicious": ["#4CAF50", "#F44336"],
    "attack_types": {
        "Normal": "#4CAF50",
        "DoS": "#F44336",
        "Probe": "#FF9800",
        "R2L": "#9C27B0",
        "U2R": "#795548"
    },
    "protocols": ["#2196F3", "#00BCD4", "#009688", "#8BC34A", "#FFEB3B"],
    "ports": ["#E91E63", "#9C27B0", "#673AB7", "#3F51B5", "#2196F3"],
    "traffic": ["#607D8B", "#795548", "#9E9E9E", "#CDDC39", "#FFC107"]
}

# GUI setup
root = tk.Tk()
root.title("Network Intrusion Detection System")

# Selection Frame
selection_frame = ttk.Frame(root, padding=10)
selection_frame.pack(fill=tk.X)

# Interface Selection
interface_frame = ttk.LabelFrame(selection_frame, text="Select Interface", padding=10)
interface_frame.pack(side=tk.LEFT, padx=5)

interface_var = tk.StringVar()
wifi_radio = ttk.Radiobutton(interface_frame, text="Wi-Fi", variable=interface_var, value="Wi-Fi")
wifi_radio.pack(side=tk.LEFT, padx=5)
lan_radio = ttk.Radiobutton(interface_frame, text="LAN", variable=interface_var, value="Ethernet")
lan_radio.pack(side=tk.LEFT, padx=5)

# Set default selection
interface_var.set("Wi-Fi")

# Packet Count Selection
count_frame = ttk.LabelFrame(selection_frame, text="Packet Count", padding=10)
count_frame.pack(side=tk.LEFT, padx=5)

count_var = tk.StringVar()
count_options = [
    ("1,000", "1000"),
    ("10,000", "10000"),
    ("100,000", "100000"),
    ("1,000,000", "1000000")
]

for text, value in count_options:
    ttk.Radiobutton(count_frame, text=text, variable=count_var, value=value).pack(side=tk.LEFT, padx=5)

# Set default selection
count_var.set("10000")

container = ttk.Frame(root)
container.pack(fill=tk.BOTH, expand=True)

canvas = tk.Canvas(container, height=500)  # Increased height for more graphs
scrollbar = ttk.Scrollbar(container, orient="horizontal", command=canvas.xview)
canvas.configure(xscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

graph_frame = ttk.Frame(canvas)
canvas.create_window((0, 0), window=graph_frame, anchor="nw")

def configure_scroll(event):
    canvas.configure(scrollregion=canvas.bbox("all"))
graph_frame.bind("<Configure>", configure_scroll)

# Button Frame
button_frame = ttk.Frame(root, padding=10)
button_frame.pack(fill=tk.X)

btn_start = ttk.Button(button_frame, text="▶ Start Capture")
btn_start.pack(side=tk.LEFT, padx=5)

btn_stop = ttk.Button(button_frame, text="■ Stop Capture", state=tk.DISABLED)
btn_stop.pack(side=tk.LEFT, padx=5)

# Status Frame
status_frame = ttk.Frame(root, padding=5)
status_frame.pack(fill=tk.X)
status_label = ttk.Label(status_frame, text="Ready to capture", foreground="blue")
status_label.pack()

# Global control
tshark_proc = None
capture_thread = None
stop_event = threading.Event()

def start_capture():
    global capture_thread, interface_name, packet_count
    
    # Get selected interface
    interface_name = interface_var.get()
    if not interface_name:
        status_label.config(text="Please select an interface first", foreground="red")
        return
    
    # Get selected packet count
    try:
        packet_count = int(count_var.get())
    except ValueError:
        status_label.config(text="Please select a valid packet count", foreground="red")
        return
    
    stop_event.clear()
    btn_start.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    status_label.config(text=f"Capturing {packet_count:,} packets on {interface_name}...", foreground="green")
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()

def stop_capture():
    global tshark_proc
    stop_event.set()
    if tshark_proc:
        try:
            tshark_proc.terminate()
        except Exception:
            pass
    btn_stop.config(state=tk.DISABLED)
    btn_start.config(state=tk.NORMAL)
    status_label.config(text="Capture stopped", foreground="red")

btn_start.config(command=start_capture)
btn_stop.config(command=stop_capture)

def capture_packets():
    global tshark_proc

    tshark_command = ["tshark", "-i", interface_name, "-c", str(packet_count), "-T", "fields"]
    for field in fields:
        tshark_command += ["-e", field]
    tshark_command += ["-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]

    try:
        tshark_proc = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            output, _ = tshark_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            tshark_proc.terminate()
            output, _ = tshark_proc.communicate()
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}", foreground="red")
        btn_start.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)
        return

    output_lines = output.decode().splitlines()
    print(output_lines)

    if not output_lines:
        status_label.config(text="No packets captured", foreground="orange")
        btn_start.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)
        return

    packets = []
    protocol_counts = {}
    port_counts = Counter()
    src_ip_counts = Counter()
    dst_ip_counts = Counter()
    packet_sizes = []
    tcp_flags_counts = Counter()
    ttl_values = []

    for line in output_lines:
        parts = [p.strip('"') for p in line.split(',')]
        if len(parts) < len(fields):
            continue
        try:
            protocol = parts[5]
            sport = parts[6] if parts[6] else "N/A"
            dport = parts[7] if parts[7] else "N/A"
            src_ip = parts[2] if parts[2] else "N/A"
            dst_ip = parts[3] if parts[3] else "N/A"
            flags = parts[8] if len(parts) > 8 else "none"
            ttl = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else -1
            length = int(parts[4])

            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            port_counts.update([sport, dport])
            src_ip_counts[src_ip] += 1
            dst_ip_counts[dst_ip] += 1
            packet_sizes.append(length)
            tcp_flags_counts[flags] += 1
            if ttl > 0:
                ttl_values.append(ttl)

            packet = {
                "no": parts[0],
                "timestamp": float(parts[1]),
                "src": src_ip,
                "dst": dst_ip,
                "length": length,
                "protocol": protocol,
                "sport": sport,
                "dport": dport,
                "flags": flags,
                "ttl": ttl,
                "window": int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else -1
            }
            packets.append(packet)
        except Exception:
            continue

    sessions = {}
    def get_session_key(pkt):
        return (pkt["src"], pkt["dst"], pkt["sport"], pkt["dport"], pkt["protocol"])

    for pkt in packets:
        key = get_session_key(pkt)
        if key not in sessions:
            sessions[key] = {
                "start_time": pkt["timestamp"],
                "end_time": pkt["timestamp"],
                "protocoltype": pkt["protocol"],
                "service": pkt["protocol"],
                "flag": pkt["flags"],
                "srcbytes": pkt["length"],
                "dstbytes": 0,
                "count": 1,
                "lastflag": pkt["flags"]
            }
        else:
            sess = sessions[key]
            sess["end_time"] = pkt["timestamp"]
            sess["srcbytes"] += pkt["length"]
            sess["count"] += 1
            sess["lastflag"] = pkt["flags"]

    rows = []
    for session in sessions.values():
        duration = session["end_time"] - session["start_time"]
        row = {
            "duration": duration,
            "protocoltype": session["protocoltype"],
            "service": session["service"],
            "flag": session["flag"],
            "srcbytes": session["srcbytes"],
            "dstbytes": session["dstbytes"],
            "wrongfragment": 0, "hot": 0, "loggedin": 0, "numcompromised": 0,
            "rootshell": 0, "suattempted": 0, "numroot": 0, "numfilecreations": 0,
            "numshells": 0, "numaccessfiles": 0, "ishostlogin": 0, "isguestlogin": 0,
            "count": session["count"], "srvcount": 0, "serrorrate": 0,
            "srvserrorrate": 0, "rerrorrate": 0, "srvrerrorrate": 0,
            "samediprate": 0, "diffsrvrate": 0, "dsthostcount": 0,
            "dsthostsrvcount": 0, "dsthostsamedsrvrate": 0,
            "dsthostdiffsrvrate": 0, "dsthostserrorrate": 0,
            "dsthostsrvserrorrate": 0, "dsthostrerrorrate": 0,
            "dsthostsrvrerrorrate": 0, "lastflag": session["lastflag"]
        }
        rows.append(row)

    df_sessions = pd.DataFrame(rows)

    le = LabelEncoder()
    for col in df_sessions.select_dtypes(include='object').columns:
        df_sessions[col] = le.fit_transform(df_sessions[col].astype(str))

    predictions = model.predict(df_sessions)
    df_sessions["prediction"] = predictions
    df_sessions["attack_type"] = df_sessions["prediction"].map(ATTACK_TYPES)
    df_sessions.to_csv("captured_sessions.csv", index=False)

    # Clear previous graphs
    for widget in graph_frame.winfo_children():
        widget.destroy()

    def draw_pie(data_dict, title, colors=None, size=(4, 4), explode=None):
        if not colors:
            colors = plt.cm.tab20.colors
        fig, ax = plt.subplots(figsize=size)
        labels, values = zip(*data_dict.items())
        
        if not explode:
            explode = [0.05] * len(values)  # Slight separation between slices
            
        wedges, _, autotexts = ax.pie(values, 
                                     labels=labels if len(labels) <= 5 else None,
                                     startangle=140, 
                                     textprops={'fontsize': 8}, 
                                     autopct=lambda p: f'{p:.1f}%' if p > 5 else '', 
                                     colors=colors,
                                     explode=explode,
                                     shadow=True)
        
        ax.set_title(title, fontsize=10, fontweight='bold', pad=20)
        
        # Only show legend if there are more than 5 categories
        if len(labels) > 5:
            ax.legend(wedges, labels, title="Categories", 
                     loc="center left", bbox_to_anchor=(1, 0.5), 
                     fontsize=7, title_fontsize=8)
        
        # Make percentage labels white for better visibility
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(8)
            
        fig.tight_layout()
        return fig

    def draw_bar(data_dict, title, color, size=(5, 4), rotation=45, horizontal=False):
        fig, ax = plt.subplots(figsize=size)
        labels, values = zip(*data_dict.items())
        
        if horizontal:
            y_pos = np.arange(len(labels))
            ax.barh(y_pos, values, color=color)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels)
            ax.invert_yaxis()  # highest value at top
        else:
            ax.bar(labels, values, color=color)
            plt.xticks(rotation=rotation, ha='right')
            
        ax.set_title(title, fontsize=10, fontweight='bold')
        fig.tight_layout()
        return fig

    def draw_histogram(data, title, color, bins=20, size=(5, 4)):
        fig, ax = plt.subplots(figsize=size)
        ax.hist(data, bins=bins, color=color, edgecolor='black', alpha=0.7)
        ax.set_title(title, fontsize=10, fontweight='bold')
        ax.grid(True, linestyle='--', alpha=0.6)
        fig.tight_layout()
        return fig

    # 1. Normal vs Malicious Packets (Pie Chart)
    normal_count = sum(1 for pred in predictions if pred == 0)
    malicious_count = len(predictions) - normal_count
    normal_vs_malicious = {
        "Normal": normal_count,
        "Malicious": malicious_count
    }
    fig1 = draw_pie(normal_vs_malicious, "Normal vs Malicious Traffic", 
                   COLOR_SCHEMES["normal_vs_malicious"], explode=[0, 0.1])
    FigureCanvasTkAgg(fig1, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 2. Top Source IP Counts (Horizontal Bar Chart)
    top_src_ips = dict(src_ip_counts.most_common(8))
    fig2 = draw_bar(top_src_ips, "Top Source IPs", "#2196F3", horizontal=True)
    FigureCanvasTkAgg(fig2, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 3. Top Destination IP Counts (Horizontal Bar Chart)
    top_dst_ips = dict(dst_ip_counts.most_common(8))
    fig3 = draw_bar(top_dst_ips, "Top Destination IPs", "#4CAF50", horizontal=True)
    FigureCanvasTkAgg(fig3, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 4. Ports Used (Pie Chart)
    filtered_ports = {k: v for k, v in port_counts.items() if k != "N/A"}
    top_ports = dict(Counter(filtered_ports).most_common(5))
    if top_ports:
        fig4 = draw_pie(top_ports, "Top Ports Used", COLOR_SCHEMES["ports"])
        FigureCanvasTkAgg(fig4, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 5. Protocol Distribution (Pie Chart)
    if protocol_counts:
        fig5 = draw_pie(protocol_counts, "Protocol Distribution", COLOR_SCHEMES["protocols"])
        FigureCanvasTkAgg(fig5, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 6. Attack Type Distribution (Pie Chart)
    attack_counts = df_sessions["attack_type"].value_counts().to_dict()
    attack_colors = [COLOR_SCHEMES["attack_types"].get(k, "#607D8B") for k in attack_counts.keys()]
    
    fig6 = draw_pie(attack_counts, "Attack Types Distribution", attack_colors, size=(5, 5))
    FigureCanvasTkAgg(fig6, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 7. Packet Size Distribution (Histogram)
    if packet_sizes:
        fig7 = draw_histogram(packet_sizes, "Packet Size Distribution", "#FF9800", bins=15)
        FigureCanvasTkAgg(fig7, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 8. TCP Flags Distribution (Bar Chart)
    if tcp_flags_counts:
        fig8 = draw_bar(dict(tcp_flags_counts.most_common(8)), "TCP Flags Distribution", "#9C27B0")
        FigureCanvasTkAgg(fig8, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 9. TTL Value Distribution (Histogram)
    if ttl_values:
        fig9 = draw_histogram(ttl_values, "TTL Value Distribution", "#00BCD4", bins=15)
        FigureCanvasTkAgg(fig9, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 10. Traffic Over Time (Line Chart)
    if packets:
        # Create time bins (e.g., 10-second intervals)
        first_time = packets[0]["timestamp"]
        last_time = packets[-1]["timestamp"]
        time_range = last_time - first_time
        bins = 10
        interval = time_range / bins
        
        time_counts = {}
        for i in range(bins):
            start = first_time + i * interval
            end = start + interval
            count = sum(1 for pkt in packets if start <= pkt["timestamp"] <= end)
            time_counts[f"{i*10}-{(i+1)*10}s"] = count
            
        fig10 = draw_bar(time_counts, "Traffic Over Time (10s intervals)", "#E91E63")
        FigureCanvasTkAgg(fig10, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # 11. Malicious Traffic by Protocol (Stacked Bar)
    if len(packets) > 0 and 'attack_type' in df_sessions.columns:
        malicious_by_proto = df_sessions[df_sessions['attack_type'] != 'Normal'].groupby('protocoltype')['attack_type'].count()
        normal_by_proto = df_sessions[df_sessions['attack_type'] == 'Normal'].groupby('protocoltype')['attack_type'].count()
        
        fig11, ax = plt.subplots(figsize=(5, 4))
        ax.bar(normal_by_proto.index, normal_by_proto.values, label='Normal', color=COLOR_SCHEMES["attack_types"]["Normal"])
        ax.bar(malicious_by_proto.index, malicious_by_proto.values, bottom=normal_by_proto.values, 
               label='Malicious', color=COLOR_SCHEMES["attack_types"]["DoS"])
        ax.set_title("Traffic by Protocol (Normal vs Malicious)", fontsize=10, fontweight='bold')
        ax.legend(fontsize=8)
        plt.xticks(rotation=45, ha='right')
        fig11.tight_layout()
        FigureCanvasTkAgg(fig11, master=graph_frame).get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)

    # Update status
    status_text = f"Analysis complete: {normal_count} normal, {malicious_count} malicious packets"
    status_label.config(text=status_text, 
                       foreground="green" if malicious_count == 0 else "red")

    btn_start.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)

root.mainloop()
'''


import subprocess
import pandas as pd
import pickle
import threading
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from collections import Counter
import numpy as np

# Set matplotlib backend to Agg to avoid threading issues
plt.switch_backend('Agg')

# Load trained model
with open("trained_model.pkl", "rb") as f:
    model = pickle.load(f)

# Default interface and packet count (will be set by user selection)
interface_name = None
packet_count = 10000

fields = [
    "_ws.col.No.", "frame.time_epoch", "ip.src", "ip.dst", "frame.len",
    "_ws.col.Protocol", "tcp.srcport", "tcp.dstport", "tcp.flags",
    "ip.ttl", "tcp.window_size_value"
]

# Attack type mapping
ATTACK_TYPES = {
    0: "Normal",
    1: "DoS",
    2: "Probe",
    3: "R2L",
    4: "U2R"
}

# Color schemes
COLOR_SCHEMES = {
    "normal_vs_malicious": ["#4CAF50", "#F44336"],
    "attack_types": {
        "Normal": "#4CAF50",
        "DoS": "#F44336",
        "Probe": "#FF9800",
        "R2L": "#9C27B0",
        "U2R": "#795548"
    },
    "protocols": ["#2196F3", "#00BCD4", "#009688", "#8BC34A", "#FFEB3B"],
    "ports": ["#E91E63", "#9C27B0", "#673AB7", "#3F51B5", "#2196F3"],
    "traffic": ["#607D8B", "#795548", "#9E9E9E", "#CDDC39", "#FFC107"]
}

class NetworkIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analysis System")
        
        # Initialize variables
        self.tshark_proc = None
        self.capture_thread = None
        self.stop_event = threading.Event()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Selection Frame
        selection_frame = ttk.Frame(self.root, padding=10)
        selection_frame.pack(fill=tk.X)

        # Interface Selection
        interface_frame = ttk.LabelFrame(selection_frame, text="Select Interface", padding=10)
        interface_frame.pack(side=tk.LEFT, padx=5)

        self.interface_var = tk.StringVar(value="Wi-Fi")
        ttk.Radiobutton(interface_frame, text="Wi-Fi", variable=self.interface_var, value="Wi-Fi").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(interface_frame, text="LAN", variable=self.interface_var, value="Ethernet").pack(side=tk.LEFT, padx=5)

        # Packet Count Selection
        count_frame = ttk.LabelFrame(selection_frame, text="Packet Count", padding=10)
        count_frame.pack(side=tk.LEFT, padx=5)

        self.count_var = tk.StringVar(value="10000")
        count_options = [
            ("1,000", "1000"),
            ("10,000", "10000"),
            ("100,000", "100000"),
            ("1,000,000", "1000000")
        ]
        for text, value in count_options:
            ttk.Radiobutton(count_frame, text=text, variable=self.count_var, value=value).pack(side=tk.LEFT, padx=5)

        # Container for graphs
        self.container = ttk.Frame(self.root)
        self.container.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(self.container, height=500)
        self.scrollbar = ttk.Scrollbar(self.container, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.graph_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.graph_frame, anchor="nw")

        self.graph_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # Button Frame
        button_frame = ttk.Frame(self.root, padding=10)
        button_frame.pack(fill=tk.X)

        self.btn_start = ttk.Button(button_frame, text="▶ Start Capture", command=self.start_capture)
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(button_frame, text="■ Stop Capture", state=tk.DISABLED, command=self.stop_capture)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # Status Frame
        status_frame = ttk.Frame(self.root, padding=5)
        status_frame.pack(fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Ready to capture", foreground="blue")
        self.status_label.pack()

    def start_capture(self):
        interface_name = self.interface_var.get()
        if not interface_name:
            self.status_label.config(text="Please select an interface first", foreground="red")
            return
        
        try:
            packet_count = int(self.count_var.get())
        except ValueError:
            self.status_label.config(text="Please select a valid packet count", foreground="red")
            return
        
        self.stop_event.clear()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_label.config(text=f"Capturing {packet_count:,} packets on {interface_name}...", foreground="green")
        
        # Clear previous graphs
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
            
        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(interface_name, packet_count),
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self):
        self.stop_event.set()
        if self.tshark_proc:
            try:
                self.tshark_proc.terminate()
            except Exception:
                pass
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_start.config(state=tk.NORMAL)
        self.status_label.config(text="Capture stopped", foreground="red")

    def capture_packets(self, interface_name, packet_count):
        tshark_command = ["tshark", "-i", interface_name, "-c", str(packet_count), "-T", "fields"]
        for field in fields:
            tshark_command += ["-e", field]
        tshark_command += ["-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]

        try:
            self.tshark_proc = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                output, _ = self.tshark_proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self.tshark_proc.terminate()
                output, _ = self.tshark_proc.communicate()
        except Exception as e:
            self.root.after(0, self.update_status, f"Error: {str(e)}", "red")
            self.root.after(0, self.enable_start_button)
            return

        output_lines = output.decode().splitlines()
        print(output_lines)

        if not output_lines:
            self.root.after(0, self.update_status, "No packets captured", "orange")
            self.root.after(0, self.enable_start_button)
            return

        # Process packets and create visualizations
        self.process_packets(output_lines)

    def process_packets(self, output_lines):
        packets = []
        protocol_counts = {}
        port_counts = Counter()
        src_ip_counts = Counter()
        dst_ip_counts = Counter()
        packet_sizes = []
        tcp_flags_counts = Counter()
        ttl_values = []

        for line in output_lines:
            parts = [p.strip('"') for p in line.split(',')]
            if len(parts) < len(fields):
                continue
            try:
                protocol = parts[5]
                sport = parts[6] if parts[6] else "N/A"
                dport = parts[7] if parts[7] else "N/A"
                src_ip = parts[2] if parts[2] else "N/A"
                dst_ip = parts[3] if parts[3] else "N/A"
                flags = parts[8] if len(parts) > 8 else "none"
                ttl = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else -1
                length = int(parts[4])

                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                port_counts.update([sport, dport])
                src_ip_counts[src_ip] += 1
                dst_ip_counts[dst_ip] += 1
                packet_sizes.append(length)
                tcp_flags_counts[flags] += 1
                if ttl > 0:
                    ttl_values.append(ttl)

                packet = {
                    "no": parts[0],
                    "timestamp": float(parts[1]),
                    "src": src_ip,
                    "dst": dst_ip,
                    "length": length,
                    "protocol": protocol,
                    "sport": sport,
                    "dport": dport,
                    "flags": flags,
                    "ttl": ttl,
                    "window": int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else -1
                }
                packets.append(packet)
            except Exception:
                continue

        sessions = {}
        def get_session_key(pkt):
            return (pkt["src"], pkt["dst"], pkt["sport"], pkt["dport"], pkt["protocol"])

        for pkt in packets:
            key = get_session_key(pkt)
            if key not in sessions:
                sessions[key] = {
                    "start_time": pkt["timestamp"],
                    "end_time": pkt["timestamp"],
                    "protocoltype": pkt["protocol"],
                    "service": pkt["protocol"],
                    "flag": pkt["flags"],
                    "srcbytes": pkt["length"],
                    "dstbytes": 0,
                    "count": 1,
                    "lastflag": pkt["flags"]
                }
            else:
                sess = sessions[key]
                sess["end_time"] = pkt["timestamp"]
                sess["srcbytes"] += pkt["length"]
                sess["count"] += 1
                sess["lastflag"] = pkt["flags"]

        rows = []
        for session in sessions.values():
            duration = session["end_time"] - session["start_time"]
            row = {
                "duration": duration,
                "protocoltype": session["protocoltype"],
                "service": session["service"],
                "flag": session["flag"],
                "srcbytes": session["srcbytes"],
                "dstbytes": session["dstbytes"],
                "wrongfragment": 0, "hot": 0, "loggedin": 0, "numcompromised": 0,
                "rootshell": 0, "suattempted": 0, "numroot": 0, "numfilecreations": 0,
                "numshells": 0, "numaccessfiles": 0, "ishostlogin": 0, "isguestlogin": 0,
                "count": session["count"], "srvcount": 0, "serrorrate": 0,
                "srvserrorrate": 0, "rerrorrate": 0, "srvrerrorrate": 0,
                "samediprate": 0, "diffsrvrate": 0, "dsthostcount": 0,
                "dsthostsrvcount": 0, "dsthostsamedsrvrate": 0,
                "dsthostdiffsrvrate": 0, "dsthostserrorrate": 0,
                "dsthostsrvserrorrate": 0, "dsthostrerrorrate": 0,
                "dsthostsrvrerrorrate": 0, "lastflag": session["lastflag"]
            }
            rows.append(row)

        df_sessions = pd.DataFrame(rows)

        le = LabelEncoder()
        for col in df_sessions.select_dtypes(include='object').columns:
            df_sessions[col] = le.fit_transform(df_sessions[col].astype(str))

        predictions = model.predict(df_sessions)
        df_sessions["prediction"] = predictions
        df_sessions["attack_type"] = df_sessions["prediction"].map(ATTACK_TYPES)
        df_sessions.to_csv("captured_sessions.csv", index=False)

        # Create visualizations
        self.create_visualizations(
            predictions, src_ip_counts, dst_ip_counts, port_counts,
            protocol_counts, packet_sizes, tcp_flags_counts, ttl_values,
            packets, df_sessions
        )

        # Update status
        normal_count = sum(1 for pred in predictions if pred == 0)
        malicious_count = len(predictions) - normal_count
        status_text = f"Analysis complete: {normal_count} normal, {malicious_count} malicious packets"
        self.root.after(0, self.update_status, status_text, "green" if malicious_count == 0 else "red")
        self.root.after(0, self.enable_start_button)

    def create_visualizations(self, predictions, src_ip_counts, dst_ip_counts, port_counts,
                            protocol_counts, packet_sizes, tcp_flags_counts, ttl_values,
                            packets, df_sessions):
        # 1. Normal vs Malicious Packets (Pie Chart)
        normal_count = sum(1 for pred in predictions if pred == 0)
        malicious_count = len(predictions) - normal_count
        normal_vs_malicious = {"Normal": normal_count, "Malicious": malicious_count}
        fig1 = self.draw_pie(normal_vs_malicious, "Normal vs Malicious Traffic", 
                            COLOR_SCHEMES["normal_vs_malicious"], explode=[0, 0.1])
        self.add_figure_to_ui(fig1)

        # 2. Top Source IP Counts (Horizontal Bar Chart)
        top_src_ips = dict(src_ip_counts.most_common(8))
        fig2 = self.draw_bar(top_src_ips, "Top Source IPs", "#2196F3", horizontal=True)
        self.add_figure_to_ui(fig2)

        # 3. Top Destination IP Counts (Horizontal Bar Chart)
        top_dst_ips = dict(dst_ip_counts.most_common(8))
        fig3 = self.draw_bar(top_dst_ips, "Top Destination IPs", "#4CAF50", horizontal=True)
        self.add_figure_to_ui(fig3)

        # 4. Ports Used (Pie Chart)
        filtered_ports = {k: v for k, v in port_counts.items() if k != "N/A"}
        top_ports = dict(Counter(filtered_ports).most_common(5))
        if top_ports:
            fig4 = self.draw_pie(top_ports, "Top Ports Used", COLOR_SCHEMES["ports"])
            self.add_figure_to_ui(fig4)

        # 5. Protocol Distribution (Pie Chart)
        if protocol_counts:
            fig5 = self.draw_pie(protocol_counts, "Protocol Distribution", COLOR_SCHEMES["protocols"])
            self.add_figure_to_ui(fig5)

        # 6. Attack Type Distribution (Pie Chart)
        attack_counts = df_sessions["attack_type"].value_counts().to_dict()
        attack_colors = [COLOR_SCHEMES["attack_types"].get(k, "#607D8B") for k in attack_counts.keys()]
        fig6 = self.draw_pie(attack_counts, "Attack Types Distribution", attack_colors, size=(5, 5))
        self.add_figure_to_ui(fig6)

        # 7. Packet Size Distribution (Histogram)
        if packet_sizes:
            fig7 = self.draw_histogram(packet_sizes, "Packet Size Distribution", "#FF9800", bins=15)
            self.add_figure_to_ui(fig7)

        # 8. TCP Flags Distribution (Bar Chart)
        if tcp_flags_counts:
            fig8 = self.draw_bar(dict(tcp_flags_counts.most_common(8)), "TCP Flags Distribution", "#9C27B0")
            self.add_figure_to_ui(fig8)

        # 9. TTL Value Distribution (Histogram)
        if ttl_values:
            fig9 = self.draw_histogram(ttl_values, "TTL Value Distribution", "#00BCD4", bins=15)
            self.add_figure_to_ui(fig9)

        # 10. Traffic Over Time (Line Chart)
        if packets:
            first_time = packets[0]["timestamp"]
            last_time = packets[-1]["timestamp"]
            time_range = last_time - first_time
            bins = 10
            interval = time_range / bins
            
            time_counts = {}
            for i in range(bins):
                start = first_time + i * interval
                end = start + interval
                count = sum(1 for pkt in packets if start <= pkt["timestamp"] <= end)
                time_counts[f"{i*10}-{(i+1)*10}s"] = count
                
            fig10 = self.draw_bar(time_counts, "Traffic Over Time (10s intervals)", "#E91E63")
            self.add_figure_to_ui(fig10)

        # 11. Malicious Traffic by Protocol (Stacked Bar)
        if len(packets) > 0 and 'attack_type' in df_sessions.columns:
            # Handle potential mismatched indices
            malicious_by_proto = df_sessions[df_sessions['attack_type'] != 'Normal'].groupby('protocoltype')['attack_type'].count()
            normal_by_proto = df_sessions[df_sessions['attack_type'] == 'Normal'].groupby('protocoltype')['attack_type'].count()
            
            # Align the indices
            all_protocols = set(malicious_by_proto.index).union(set(normal_by_proto.index))
            malicious_by_proto = malicious_by_proto.reindex(all_protocols, fill_value=0)
            normal_by_proto = normal_by_proto.reindex(all_protocols, fill_value=0)
            
            fig11, ax = plt.subplots(figsize=(5, 4))
            ax.bar(normal_by_proto.index, normal_by_proto.values, label='Normal', color=COLOR_SCHEMES["attack_types"]["Normal"])
            ax.bar(malicious_by_proto.index, malicious_by_proto.values, bottom=normal_by_proto.values, 
                   label='Malicious', color=COLOR_SCHEMES["attack_types"]["DoS"])
            ax.set_title("Traffic by Protocol (Normal vs Malicious)", fontsize=10, fontweight='bold')
            ax.legend(fontsize=8)
            plt.xticks(rotation=45, ha='right')
            fig11.tight_layout()
            self.add_figure_to_ui(fig11)

    def draw_pie(self, data_dict, title, colors=None, size=(4, 4), explode=None):
        if not colors:
            colors = plt.cm.tab20.colors
        fig, ax = plt.subplots(figsize=size)
        labels, values = zip(*data_dict.items())
        
        if not explode:
            explode = [0.05] * len(values)
            
        wedges, _, autotexts = ax.pie(values, 
                                     labels=labels if len(labels) <= 5 else None,
                                     startangle=140, 
                                     textprops={'fontsize': 8}, 
                                     autopct=lambda p: f'{p:.1f}%' if p > 5 else '', 
                                     colors=colors,
                                     explode=explode,
                                     shadow=True)
        
        ax.set_title(title, fontsize=10, fontweight='bold', pad=20)
        
        if len(labels) > 5:
            ax.legend(wedges, labels, title="Categories", 
                     loc="center left", bbox_to_anchor=(1, 0.5), 
                     fontsize=7, title_fontsize=8)
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(8)
            
        fig.tight_layout()
        return fig

    def draw_bar(self, data_dict, title, color, size=(5, 4), rotation=45, horizontal=False):
        fig, ax = plt.subplots(figsize=size)
        labels, values = zip(*data_dict.items())
        
        if horizontal:
            y_pos = np.arange(len(labels))
            ax.barh(y_pos, values, color=color)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels)
            ax.invert_yaxis()
        else:
            ax.bar(labels, values, color=color)
            plt.xticks(rotation=rotation, ha='right')
            
        ax.set_title(title, fontsize=10, fontweight='bold')
        fig.tight_layout()
        return fig

    def draw_histogram(self, data, title, color, bins=20, size=(5, 4)):
        fig, ax = plt.subplots(figsize=size)
        ax.hist(data, bins=bins, color=color, edgecolor='black', alpha=0.7)
        ax.set_title(title, fontsize=10, fontweight='bold')
        ax.grid(True, linestyle='--', alpha=0.6)
        fig.tight_layout()
        return fig

    def add_figure_to_ui(self, fig):
        # This must be called from the main thread
        def _add_figure():
            canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(side=tk.LEFT, padx=10, pady=10)
            plt.close(fig)  # Close the figure to prevent memory leaks
            
        self.root.after(0, _add_figure)

    def update_status(self, text, color):
        self.status_label.config(text=text, foreground=color)

    def enable_start_button(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkIDSApp(root)
    root.mainloop()