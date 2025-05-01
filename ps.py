import subprocess
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from sklearn.preprocessing import LabelEncoder

# Load the trained model
model_filename = "packet_classifier.pkl"
model = joblib.load(model_filename)

# LabelEncoder for 'frame.protocols' column
le = LabelEncoder()

# Feature names corresponding to the model's training
feature_names = [
    "frame.len", "ip.proto", "tcp.flags", "udp.length", 
    "icmp.type", "icmp.code", "frame.protocols"
]

# Protocol map for converting protocol numbers to names
protocol_map = {
    1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 443: "TLS", 80: "HTTP", 443: "HTTPS"
}

# Function to capture packets using TShark (Wi-Fi Interface)
def capture_packets(interface="wlan0", packet_count=100):
    # Run TShark command to capture packets from Wi-Fi interface
    command = f"tshark -i {interface} -c {packet_count} -T fields -e frame.len -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto -e tcp.flags -e udp.length -e icmp.type -e icmp.code -e frame.protocols"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    output, error = process.communicate()
    
    if process.returncode != 0:
        print(f"Error capturing packets: {error.decode()}")
        return []
    
    # Process captured packet data
    captured_packets = output.decode().strip().splitlines()
    return [packet.split("\t") for packet in captured_packets]

# Function to process and convert the packet features (excluding IPs and ports)
def process_features(packet):
    # Process each field, converting to integer if possible, excluding IP fields and port fields
    processed_features = []
    for i, value in enumerate(packet[4:]):  # Start from index 4, as first four are IPs and ports
        try:
            # If the value is a hex value (starts with '0x'), convert it to integer
            if value.startswith('0x'):
                processed_features.append(int(value, 16))
            # If it's a valid number, convert it to integer
            elif value and value.isdigit():
                processed_features.append(int(value))
            else:
                # If it's an empty value, replace with 0 (or you can use a default value)
                processed_features.append(0)
        except ValueError:
            # Handle any other errors by appending 0 (or another default value)
            processed_features.append(0)
    return processed_features

# Function to predict attack or normal for captured packet
def predict_packet(features):
    # Ensure the features are in a DataFrame
    features_df = pd.DataFrame([features], columns=feature_names)
    
    # Encode the 'frame.protocols' feature
    features_df['frame.protocols'] = le.fit_transform(features_df['frame.protocols'])
    
    # Make the prediction using the model
    prediction = model.predict(features_df)[0]
    return "Attack" if prediction == 1 else "Normal"

# Main function to capture and predict packets
def main():
    # Dictionaries to store port counts, IP counts, and protocol counts
    src_ip_counts = defaultdict(int)
    dst_ip_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    src_port_counts = defaultdict(int)
    dst_port_counts = defaultdict(int)
    prediction_counts = {"Normal": 0, "Attack": 0}
    
    # Capture packets from the Wi-Fi interface
    print("Capturing packets from Wi-Fi interface...")
    packets = capture_packets(interface="Wi-Fi", packet_count=200)  # Capture 100 packets as an example
    
    # Process each captured packet and make predictions
    for packet in packets:
        # Ensure packet has the correct number of features (11 fields: IPs, ports, and 7 features)
        if len(packet) == 11:
            # Extract source and destination IPs (do not use them for prediction)
            src_ip = packet[1]
            dst_ip = packet[2]
            
            # Update IP counts
            src_ip_counts[src_ip] += 1
            dst_ip_counts[dst_ip] += 1
            
            # Extract source and destination ports
            src_port = packet[3]
            dst_port = packet[4]
            
            # Update port counts
            src_port_counts[src_port] += 1
            dst_port_counts[dst_port] += 1
            
            # Extract protocol (ip.proto) and update protocol count
            protocol_value = packet[5]  # Extract the protocol field (ip.proto)
            
            # Check if the protocol field is not empty before converting it to an integer
            if protocol_value:
                try:
                    protocol_num = int(protocol_value)  # Convert to integer
                    protocol = protocol_map.get(protocol_num, f"Unknown({protocol_num})")
                    protocol_counts[protocol] += 1
                except ValueError:
                    print(f"Invalid protocol value: {protocol_value}")
            else:
                print(f"Empty protocol field in packet: {packet}")
            
            # Process and convert packet features (excluding IPs and ports)
            features = process_features(packet)  # Skip IPs and ports as they are not used in the model
            
            # Make the prediction
            prediction = predict_packet(features)
            prediction_counts[prediction] += 1  # Count the prediction as either "Normal" or "Attack"
            print(f"Packet: {packet} => Prediction: {prediction}")
        else:
            print(f"Invalid packet format: {packet}")
    
    # Print the top 5 source IP counts
    print("\nTop 5 Source IPs:")
    top_src_ips = Counter(src_ip_counts).most_common(5)
    for ip, count in top_src_ips:
        print(f"Source IP {ip}: {count} occurrences")
    
    # Print the top 5 destination IP counts
    print("\nTop 5 Destination IPs:")
    top_dst_ips = Counter(dst_ip_counts).most_common(5)
    for ip, count in top_dst_ips:
        print(f"Destination IP {ip}: {count} occurrences")
    
    # Print the protocol counts (e.g., ICMP, TCP, UDP, etc.)
    print("\nProtocols Count:")
    for protocol, count in protocol_counts.items():
        print(f"Protocol {protocol}: {count} occurrences")
    
    # Print the counts for source and destination ports
    print("\nSource Port Counts:")
    for port, count in src_port_counts.items():
        print(f"Port {port}: {count} occurrences")
    
    print("\nDestination Port Counts:")
    for port, count in dst_port_counts.items():
        print(f"Port {port}: {count} occurrences")
    
    # Print the final counts for predictions
    print(f"\nTotal Normal Packets: {prediction_counts['Normal']}")
    print(f"Total Attack Packets: {prediction_counts['Attack']}")

if __name__ == "__main__":
    main()