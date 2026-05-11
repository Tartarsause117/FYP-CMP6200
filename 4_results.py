import sqlite3
import os
import hashlib
import json
from datetime import datetime

# File paths for the two databases
DB_MEDIATED = "cloud_mediated_forensics.db"
DB_DIRECT = "cloud_direct_forensics.db"

def calculate_canonical_hash(payload_json):
    """
    Ensures JSON is hashed identically by sorting keys before 
    cryptographic computation[cite: 146, 185].
    """
    try:
        data = json.loads(payload_json)
        # sort_keys=True is critical for forensic consistency
        canonical_json = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical_json.encode()).hexdigest()
    except:
        return "ERROR"

def analyze_forensic_db(db_path, mode_label):
    if not os.path.exists(db_path):
        print(f"[!] Warning: {db_path} not found. Skip {mode_label} analysis.")
        return None

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT DISTINCT device_id FROM cloud_records")
    devices = [row[0] for row in cursor.fetchall()]
    
    report_data = {}

    for dev in devices:
        cursor.execute("""SELECT sequence_num, timestamp_source, latency, integrity, 
                                 payload, edge_hash, cloud_hash
                          FROM cloud_records WHERE device_id = ? 
                          ORDER BY sequence_num ASC""", (dev,))
        records = cursor.fetchall()

        if not records:
            continue

        total_received = len(records)
        first_seq = records[0][0]
        last_seq = records[-1][0]
        expected_count = last_seq - first_seq + 1
        lost_count = expected_count - total_received
        
        latencies = [r[2] for r in records if r[2] is not None]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        
        # Manual re-calculation to verify the chain of custody
        mismatch_count = 0
        if "Mediated" in mode_label or "Mode 1" in mode_label:
            for r in records:
                stored_payload = r[4]
                stored_edge_hash = r[5] # The original edge hash
                
                # Perform real-time audit of data at rest
                actual_current_hash = calculate_canonical_hash(stored_payload)
                
                if actual_current_hash != stored_edge_hash:
                    mismatch_count += 1

        # Find where sequence jumps 
        gaps = []
        if "Camera" in dev: 
            for i in range(len(records) - 1):
                curr_seq = records[i][0]
                next_seq = records[i+1][0]
        
                if next_seq > curr_seq + 1:
                    num_lost = next_seq - curr_seq - 1
                    t1 = datetime.fromisoformat(records[i][1])
                    t2 = datetime.fromisoformat(records[i+1][1])
            
                    raw_gap = (t2 - t1).total_seconds()
                    # Adjustment for the 1.0s expected interval
                    actual_outage_estimate = raw_gap - (1.0 * (num_lost))
                    gaps.append((num_lost, raw_gap, actual_outage_estimate))

        report_data[dev] = {
            "received": total_received,
            "lost": lost_count,
            "loss_rate": (lost_count / expected_count) * 100 if expected_count > 0 else 0,
            "avg_lat": avg_lat,
            "mismatches": mismatch_count,
            "gaps": gaps
        }

    conn.close()
    return report_data

def generate_comparison_report():
    mediated = analyze_forensic_db(DB_MEDIATED, "Edge-Mediated (Mode 1)")
    direct = analyze_forensic_db(DB_DIRECT, "Direct-to-Cloud (Mode 2)")

    print("="*90)
    print(f"FORENSIC ARCHITECTURE COMPARISON REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*90)

    all_devs = set()
    if mediated: all_devs.update(mediated.keys())
    if direct: all_devs.update(direct.keys())

    for dev in sorted(all_devs):
        print(f"\nDEVICE: {dev}")
        print("-" * 40)
        
        print(f"{'Metric':<20} | {'Edge-Mediated (A)':<20} | {'Direct-to-Cloud (B)':<20}")
        print("-" * 65)

        m_stats = mediated.get(dev, {}) if mediated else {}
        d_stats = direct.get(dev, {}) if direct else {}

        def fmt(val, suffix=""): 
            return f"{val}{suffix}" if val is not None and val != {} else "N/A"

        print(f"{'Packets Received':<20} | {fmt(m_stats.get('received')):<20} | {fmt(d_stats.get('received')):<20}")
        print(f"{'Packets Lost':<20} | {fmt(m_stats.get('lost')):<20} | {fmt(d_stats.get('lost')):<20}")
        print(f"{'Loss %':<20} | {fmt(round(m_stats.get('loss_rate', 0), 2), '%'):<20} | {fmt(round(d_stats.get('loss_rate', 0), 2), '%'):<20}")
        print(f"{'Avg Latency':<20} | {fmt(round(m_stats.get('avg_lat', 0), 4), 's'):<20} | {fmt(round(d_stats.get('avg_lat', 0), 4), 's'):<20}")
        print(f"{'Hash Mismatches':<20} | {fmt(m_stats.get('mismatches')):<20} | {'N/A (Direct)':<20}")

        if d_stats.get("gaps"):
            print("\n  [!] MODE B GAP ANALYSIS (Forensic Blind Spot):")
            for num, raw_dur, adj_dur in d_stats["gaps"]:
                print(f"      - {num} packets lost over {raw_dur:.2f}s (Est. Outage: {adj_dur:.2f}s)")

    print("\n" + "="*90)
    print("END OF REPORT")

if __name__ == "__main__":
    generate_comparison_report()