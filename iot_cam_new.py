import requests
import string
import random
import json
import time
import datetime
import uuid

EDGE_NODE_URL = "http://192.168.2.6:8080/ingest" 
CLOUD_DIRECT_URL = "http://20.0.0.2:5000/ingest" # Direct Cloud Ingest endpoint
DEVICE_ID = "Front_Door_Camera_01"
DEVICE_TYPE = "video_metadata"
TOTAL_PACKETS = 100 
INTERVAL = 0.1 

def run_test(mode):
    print(f"\n--- Starting Test: {DEVICE_ID} in Mode {mode} ---")
    
    for seq in range(1, TOTAL_PACKETS + 1):
        payload = {"frame_id": str(uuid.uuid4())[:8], "motion_score": 92.4}
        
        packet = {
            "device_id": DEVICE_ID,
            "type": DEVICE_TYPE,
            "sequence": seq,
            "timestamp_sensor": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "payload": payload
        }

        # Edge to cloud mode
        if mode == "1":
            try:
                # First attempt: Edge Node
                res = requests.post(EDGE_NODE_URL, json=packet, timeout=2)
                if res.status_code == 201:
                    print(f"[{seq}/{TOTAL_PACKETS}] Secured via Edge Node")
                else:
                    raise requests.exceptions.RequestException
            except requests.exceptions.RequestException:
                # Failover attempt: Direct to Cloud, work in progress, not implemented correctly
                try:
                    print(f"[{seq}/{TOTAL_PACKETS}] Edge Unreachable. Attempting Direct-to-Cloud Failover...")
                    requests.post(CLOUD_DIRECT_URL, json=packet, timeout=2)
                    print(f"[{seq}/{TOTAL_PACKETS}] Secured via Direct Cloud Failover")
                except:
                    print(f"[{seq}/{TOTAL_PACKETS}] CRITICAL: Both paths failed. Data Lost.")

        # Direct to cloud mode
        elif mode == "2":
            try:
                requests.post(CLOUD_DIRECT_URL, json=packet, timeout=2)
                print(f"[{seq}/{TOTAL_PACKETS}] Sent Direct-to-Cloud")
            except:
                print(f"[{seq}/{TOTAL_PACKETS}] Failed: Cloud Unreachable (No local buffer)")

        time.sleep(INTERVAL)
    
    print(f"--- {DEVICE_ID} Test Complete ---")

if __name__ == "__main__":
    print("="*40)
    print("  IOT CAMERA SIMULATOR")
    print("="*40)
    print("Select Simulation Architecture:")
    print("1: Edge-First (Try Edge Node, Failover to Cloud)")
    print("2: Direct-Only (Skip Edge, Send directly to Cloud)")
    
    user_choice = input("\nEnter Mode (1 or 2): ").strip()
    
    if user_choice in ["1", "2"]:
        run_test(user_choice)
    else:
        print("[!] Invalid selection. Exiting.")
