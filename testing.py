
import subprocess
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from sklearn.preprocessing import LabelEncoder
import socket
import random
import time
import threading

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
def capture_packets(interface="Wi-Fi", packet_count=200):
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

# Function to simulate DoS attack traffic
def simulate_dos_attack(target_ip, target_port, packet_count=1000):
    # Simulate a simple DoS attack by sending random UDP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (target_ip, target_port)

    for _ in range(packet_count):
        # Create a random payload for the UDP packet
        message = bytes([random.randint(0, 255) for _ in range(100)])
        sock.sendto(message, target)
        print(f"Sent packet to {target_ip}:{target_port}")
        time.sleep(0.1)  # Add delay to mimic real traffic

# Main function to simulate attack, capture packets, and predict
def simulate_attack_and_predict(interface="Wi-Fi", target_ip="192.168.29.112", target_port=12345):
    # Dictionaries to store counts for packet classification
    attack_count = 0
    normal_count = 0
    
    # Function to run attack and capture packets concurrently
    def attack_thread():
        # Simulate the DoS attack
        simulate_dos_attack(target_ip, target_port, packet_count=500)

    def capture_thread():
        # Capture packets from the Wi-Fi interface
        print("Capturing packets from Wi-Fi interface...")
        packets = capture_packets(interface=interface, packet_count=200)  # Capture 200 packets
        
        # Process each captured packet and make predictions
        for packet in packets:
            if len(packet) == 11:
                features = process_features(packet)  # Process packet excluding IPs and ports
                prediction = predict_packet(features)  # Predict if it's an attack or normal
                
                if prediction == "Attack":
                    nonlocal attack_count
                    attack_count += 1
                else:
                    nonlocal normal_count
                    normal_count += 1
                
                print(f"Packet: {packet} => Prediction: {prediction}")
        
        # Print the results
        print("\nTest Results:")
        print(f"Total Normal Packets: {normal_count}")
        print(f"Total Attack Packets: {attack_count}")
        print(f"Accuracy: {attack_count / (attack_count + normal_count) * 100:.2f}%")

    # Start the attack and capture threads
    attack_thread = threading.Thread(target=attack_thread)
    capture_thread = threading.Thread(target=capture_thread)
    
    attack_thread.start()  # Start the attack simulation
    capture_thread.start()  # Start the packet capture
    
    # Wait for both threads to complete
    attack_thread.join()
    capture_thread.join()

# Run the simulation
simulate_attack_and_predict(interface="Wi-Fi")
