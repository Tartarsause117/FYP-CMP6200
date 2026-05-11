import os
import json
import sqlite3
import hashlib
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)


# Two separate databases for the comparison
DB_EDGE_PATH = "cloud_mediated_forensics.db"
DB_DIRECT_PATH = "cloud_direct_forensics.db"

RUN_MODE = None 

def init_db(db_name):
    """Initializes the database schema for the selected mode."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS cloud_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id TEXT,
                        sequence_num INTEGER,
                        timestamp_source TEXT,
                        timestamp_cloud TEXT,
                        payload TEXT,
                        edge_hash TEXT,
                        cloud_hash TEXT,
                        integrity TEXT,
                        latency REAL
                    )''')
    conn.commit()
    conn.close()

def compute_sha256(data):
    json_data = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(json_data).hexdigest()

@app.route('/store', methods=['POST'])
def handle_edge_mediated():
    if RUN_MODE != "1":
        return jsonify({"error": "Cloud is in Direct-Ingest Mode"}), 403

    arrival_time = datetime.datetime.now(datetime.timezone.utc)
    packet = request.get_json()
    
    device_id = packet.get("device_id")
    ts_edge_str = packet.get("timestamp_edge")
    payload = packet.get("data")
    edge_hash = packet.get("edge_hash")
    
    # Extract sequence from the payload if available
    seq = payload.get("sequence") if isinstance(payload, dict) else None

# Forensic Verification
    cloud_hash = compute_sha256(payload)
    integrity = (cloud_hash == edge_hash)
    
    ts_edge = datetime.datetime.fromisoformat(ts_edge_str).replace(tzinfo=datetime.timezone.utc)
    latency = (arrival_time - ts_edge).total_seconds()

    # Record to Mediated DB
    save_to_db(DB_EDGE_PATH, device_id, seq, ts_edge_str, arrival_time.isoformat(), 
               json.dumps(payload), edge_hash, cloud_hash, str(integrity), latency)

    print(f"[MODE 1] Received {device_id} (Seq: {seq}) via Edge. Integrity: {integrity}")
    return jsonify({"status": "received", "integrity": "valid" if integrity else "CORRUPT"}), 200

@app.route('/ingest', methods=['POST'])
def handle_direct_ingest():
    """Endpoint for Mode 2: Data arriving directly from IoT Devices."""
    if RUN_MODE != "2":
        return jsonify({"error": "Cloud is in Edge-Mediated Mode"}), 403

    arrival_time = datetime.datetime.now(datetime.timezone.utc)
    packet = request.get_json()
    
    device_id = packet.get("device_id")
    ts_sensor = packet.get("timestamp_sensor")
    payload = packet.get("payload")
    seq = packet.get("sequence")

    # the Cloud performs the hashing upon receipt
    cloud_hash = compute_sha256(payload)
    
    # Calculate Latency
    ts_start = datetime.datetime.fromisoformat(ts_sensor)
    latency = (arrival_time - ts_start).total_seconds()

    # Record to Direct DB, edge_hash is recorded as NULL
    save_to_db(DB_DIRECT_PATH, device_id, seq, ts_sensor, arrival_time.isoformat(), 
               json.dumps(payload), None, cloud_hash, "N/A (Direct)", latency)

    print(f"[MODE 2] Received {device_id} (Seq: {seq}) DIRECTLY. Latency: {latency:.4f}s")
    return jsonify({"status": "received", "mode": "direct"}), 200

def save_to_db(db, dev_id, seq, ts_s, ts_c, payload, e_hash, c_hash, integrity, lat):
    """Helper to persist forensic records."""
    try:
        conn = sqlite3.connect(db)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO cloud_records 
                          (device_id, sequence_num, timestamp_source, timestamp_cloud, payload, edge_hash, cloud_hash, integrity, latency) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (dev_id, seq, ts_s, ts_c, payload, e_hash, c_hash, integrity, lat))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] DB Error: {e}")

if __name__ == '__main__':
    print("="*40)
    print("  CLOUD SERVER")
    print("="*40)
    print("Select Mode:")
    print("1: Edge-Mediated Path (IoT -> Edge -> Cloud)")
    print("2: Direct-to-Cloud Path (IoT -> Cloud)")
    
    choice = input("\nEnter Mode (1 or 2): ").strip()
    
    if choice == "1":
        RUN_MODE = "1"
        init_db(DB_EDGE_PATH)
        print(f"[*] ACTIVE: Mode 1 (Edge-Mediated). Writing to {DB_EDGE_PATH}")
    elif choice == "2":
        RUN_MODE = "2"
        init_db(DB_DIRECT_PATH)
        print(f"[*] ACTIVE: Mode 2 (Direct-to-Cloud). Writing to {DB_DIRECT_PATH}")
    else:
        print("[!] Invalid selection. Exiting.")
        exit()

    # Listen on all interfaces 
    app.run(host='0.0.0.0', port=5000)
