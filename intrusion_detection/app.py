from flask import Flask, jsonify, render_template
import joblib
import threading
import numpy as np
import os
from scapy.all import sniff, IP, TCP, UDP
import subprocess

app = Flask(__name__)

# Load the trained model
MODEL_PATH = "/home/abhishek/Documents/intrusion_detection/model/MLDF_model_lightgbm_optimized.joblib"
model = joblib.load(MODEL_PATH)

# Intrusion class mapping
intrusion_classes = {
    0: "Benign",
    1: "Bot",
    2:"DDoS",
    3:"DoS GoldenEye",
    4:"DoS Hulk",
    5:"DoS Slowhttptest",
    6:"DoS slowloris",
    7:"FTP-Patator",
    8:"Heartbleed",
    9:"Infiltration",
    10:"PortScan",
    11:"SSH-Patator",
    12:"Web Attack-Brute Force",
    13:"Web Attack-SQL Injection",
    14:"Web Attack-XSS"

    '''0: "Normal",
    1: "DDoS Attack",
    2: "Port Scan",
    3: "Botnet Activity",
    4: "Brute Force Attack",
    5: "Phishing Attempt",
    6: "Malware Traffic",
    7: "Data Exfiltration",
    8: "SQL Injection",
    9: "XSS Attack"'''
}

# Store live packet features
packet_data = []

# Get honeypot IP dynamically
def get_honeypot_ip():
    cmd = "sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' recursing_wiles"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

HONEYPOT_IP = get_honeypot_ip()
HONEYPOT_PORT = 2222

# Redirect all SSH traffic to honeypot
def redirect_all_to_honeypot():
    command = f"sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination {HONEYPOT_IP}:{HONEYPOT_PORT}"
    os.system(command)
    print(f"[ALERT] SSH traffic redirected to honeypot at {HONEYPOT_IP}:{HONEYPOT_PORT}")

# Extract features from network packets
def extract_features(packet):
    try:
        features = np.zeros(78, dtype=int)  # Placeholder for missing values
        if hasattr(packet, "dport"):
            features[0] = int(packet.dport)  # Destination port
        if packet:
            packet_length = len(packet)
            features[4] = int(packet_length)  # Total length of forward packets
            features[6] = int(packet_length)  # Max forward packet length
        return features
    except Exception as e:
        print(f"Feature Extraction Error: {str(e)}")
        return np.zeros(78, dtype=int)

# Capture packets and process them
def packet_callback(packet):
    feature_vector = extract_features(packet)
    if len(packet_data) >= 10:
        packet_data.pop(0)
    packet_data.append(feature_vector)

def start_sniffing():
    sniff(prn=packet_callback, store=0)

threading.Thread(target=start_sniffing, daemon=True).start()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/live_data")
def live_data():
    try:
        if not packet_data:
            features = np.random.randint(0, 255, size=(1, 78)).astype(int)  # Simulated normal traffic
            intrusion_index = 0
        else:
            features = np.array(packet_data[-1]).reshape(1, -1).astype(int)
            prediction = model.predict(features, raw_score=True)  # Get raw scores
            intrusion_index = int(np.argmax(prediction))
            confidence = float(abs(prediction[0][intrusion_index]))  # Use absolute score as confidence
            
            print(f"Predicted Intrusion: {intrusion_classes.get(intrusion_index)} with Confidence: {confidence}")
            if confidence < 5:  # Adjust this threshold based on your model
                intrusion_index = 0  # Ignore low-confidence predictions

        intrusion_name = intrusion_classes.get(intrusion_index, "Unknown Attack")

        if intrusion_index > 0:
            print(f"[ALERT] Detected: {intrusion_name}, redirecting traffic to honeypot!")
            redirect_all_to_honeypot()

        return jsonify({
            "features": features.tolist(),
            "intrusion_index": intrusion_index,
            "intrusion_name": intrusion_name,
            "ping_time": round(float(np.random.uniform(10, 100)), 2),
            "is_redirected": bool(intrusion_index > 0)
        })
    except Exception as e:
        print("Prediction Error:", str(e))
        return jsonify({"status": "Error", "error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)