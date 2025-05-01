import pandas as pd
import numpy as np
import random
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# --------- Synthetic Packet Data Generation ---------

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))  # Avoid 0 and 255

def random_mac():
    return ":".join("%02x" % random.randint(0, 255) for _ in range(6))

# TShark common protocol names
protocol_stacks = [
    "eth:ethertype:ip:tcp",
    "eth:ethertype:ip:udp",
    "eth:ethertype:ip:icmp",
    "eth:ethertype:ip:tcp:http",
    "eth:ethertype:ip:udp:dns",
    "eth:ethertype:ip:tcp:tls",
    "eth:ethertype:ip:udp:ntp",
]

def generate_synthetic_packets(num_packets=50000, attack_ratio=0.3):
    data = []

    for _ in range(num_packets):
        time = round(random.uniform(0, 600), 6)  # up to 10 minutes
        src_mac = random_mac()
        dst_mac = random_mac()
        src_ip = random_ip()
        dst_ip = random_ip()
        ip_proto = random.choice([1, 6, 17])  # ICMP=1, TCP=6, UDP=17
        frame_len = random.randint(60, 1514)  # Ethernet frame size

        tcp_flags = 0
        udp_length = 0
        icmp_type = 0
        icmp_code = 0
        protocols = random.choice(protocol_stacks)

        # Label attack or normal
        is_attack = np.random.rand() < attack_ratio

        if ip_proto == 6:  # TCP
            if is_attack:
                tcp_flags = 0x02  # SYN
            else:
                tcp_flags = random.choice([0x10, 0x18, 0x11, 0x12])  # ACKs, etc.

        elif ip_proto == 17:  # UDP
            udp_length = random.randint(20, 1200)
            if is_attack:
                udp_length = random.randint(1, 15)  # abnormal small UDP

        elif ip_proto == 1:  # ICMP
            if is_attack:
                icmp_type = 8  # echo request
                icmp_code = 0
            else:
                icmp_type = random.choice([0, 8, 3])
                icmp_code = random.choice([0, 1, 3])

        label = 1 if is_attack else 0

        data.append([time, src_mac, dst_mac, src_ip, dst_ip, ip_proto,
            frame_len, tcp_flags, udp_length,
            icmp_type, icmp_code, protocols, label
        ])

    columns = [
        "frame.time_relative", "eth.src", "eth.dst",
        "ip.src", "ip.dst", "ip.proto", "frame.len",
        "tcp.flags", "udp.length", "icmp.type", "icmp.code",
        "frame.protocols", "label"
    ]

    df = pd.DataFrame(data, columns=columns)
    return df

# --------- Model Training and Testing ---------

def train_and_save_model(df, model_filename="packet_classifier.pkl"):
    # Features and Labels
    feature_cols = [
        "frame.len", "ip.proto", "tcp.flags",
        "udp.length", "icmp.type", "icmp.code", "frame.protocols"
    ]
    
    # LabelEncoder for categorical 'frame.protocols' column
    le = LabelEncoder()
    df['frame.protocols'] = le.fit_transform(df['frame.protocols'])
    
    X = df[feature_cols]
    y = df["label"]

    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42
    )

    # Model
    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)

    # Evaluation
    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(model, model_filename)
    print(f"Model saved as {model_filename}")

def predict_packet(model_filename, features):
    # Load the trained model
    model = joblib.load(model_filename)

    # Ensure features are in a DataFrame with the correct column names
    feature_names = ["frame.len", "ip.proto", "tcp.flags", "udp.length", "icmp.type", "icmp.code", "frame.protocols"]
    features_df = pd.DataFrame([features], columns=feature_names)

    # Ensure 'frame.protocols' is encoded before prediction
    le = LabelEncoder()
    features_df['frame.protocols'] = le.fit_transform(features_df['frame.protocols'])

    # Make prediction
    prediction = model.predict(features_df)[0]
    return prediction

# --------- Main Execution ---------

if __name__ == "__main__":
    print("Generating synthetic dataset...")
    df_packets = generate_synthetic_packets(num_packets=50000, attack_ratio=0.3)
    df_packets.to_csv("synthetic_tshark_packets.csv", index=False)
    print("Dataset generated and saved as 'synthetic_tshark_packets.csv'.")

    print("Training and testing the model...")
    train_and_save_model(df_packets, model_filename="packet_classifier.pkl")

    # Example: Testing the trained model with dummy features
    print("Testing the trained model with dummy features...")
    dummy_features = np.array([100, 6, 0x10, 1200, 8, 0, 6])  # Example feature vector with 7 values
    prediction = predict_packet("packet_classifier.pkl", dummy_features)
    print(f"Prediction for dummy features: {prediction}")
