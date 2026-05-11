import datetime
import requests
import sqlite3
import time
import json
import threading
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Config
DB_NAME = "forensic_buffer.db"
CLOUD_URL = "http://20.0.0.2:5000/store" 
EDGE_ID = "Edge_Node_01"

# database logic and initalization
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Write-Ahead Logging allows simultaneous reading and writing
    cursor.execute("PRAGMA journal_mode=WAL;") 
    cursor.execute('''CREATE TABLE IF NOT EXISTS evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id TEXT,
                        sequence_num INTEGER,
                        timestamp_edge TEXT,
                        payload TEXT,
                        hash_sha256 TEXT,
                        status TEXT DEFAULT 'buffered'
                    )''')
    conn.commit()
    conn.close()

def compute_sha256(data):
    """Standardized hashing with sorted keys for forensic consistency."""
    # sort_keys=True is important so Edge and Cloud generate the same hash
    encoded_data = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(encoded_data).hexdigest()

# Ingest Route(IoT -> Edge)
@app.route('/ingest', methods=['POST'])
def edge_ingest():
    packet = request.get_json()
    
    device_id = packet.get("device_id")
    seq = packet.get("sequence") 
    payload = packet.get("payload")
    payload["sequence"] = seq    
    # Generate forensic hash at the receipt of data.
    edge_hash = compute_sha256(payload)
    timestamp_edge = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO evidence 
                              (device_id, sequence_num, timestamp_edge, payload, hash_sha256) 
                              VALUES (?, ?, ?, ?, ?)''', 
                           (device_id, seq, timestamp_edge, json.dumps(payload), edge_hash))
            conn.commit()
        return jsonify({"status": "buffered", "edge_hash": edge_hash}), 201
    except Exception as e:
        print(f"[!] Ingestion Error: {e}")
        return jsonify({"error": str(e)}), 500

# Sync (Edge -> Cloud)
def cloud_sync_worker():
    """Background thread that pushes buffered records to the Cloud."""
    print("[*] Cloud Sync Worker Started...")
    while True:
        try:
            # 1. Fetch 5 at a time to prevent database locks
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("""SELECT id, device_id, sequence_num, timestamp_edge, payload, hash_sha256 
                                  FROM evidence WHERE status='buffered' LIMIT 5""")
                records = cursor.fetchall()

            for row in records:
                db_id, dev_id, seq, ts_edge, pay_json, e_hash = row
                
                # Reconstruct packet for Cloud
                sync_packet = {
                    "device_id": dev_id,
                    "timestamp_edge": ts_edge,
                    "edge_hash": e_hash,
                    "data": json.loads(pay_json)
                }
                # Put sequence into data for Cloud extraction
                sync_packet["data"]["sequence"] = seq

                try:
                    response = requests.post(CLOUD_URL, json=sync_packet, timeout=5)
                    # Handle both 200 and 201 success codes
                    if response.status_code in [200, 201]:
                        # Update status immediately using a fresh connection
                        with sqlite3.connect(DB_NAME, timeout=10) as update_conn:
                            update_cursor = update_conn.cursor()
                            update_cursor.execute("UPDATE evidence SET status='synced' WHERE id=?", (db_id,))
                            update_conn.commit()
                        print(f"[+] Synced {dev_id} (Seq: {seq})")
                except requests.exceptions.RequestException:
                    # Network down wait for the next cycle
                    pass

        except Exception as e:
            print(f"[!] Worker Error: {e}")
            
        time.sleep(0.1) # Poll for new data every tenth of a second

if __name__ == "__main__":
    init_db()
    # Run sync worker in background
    threading.Thread(target=cloud_sync_worker, daemon=True).start()
    app.run(host='0.0.0.0', port=8080)
