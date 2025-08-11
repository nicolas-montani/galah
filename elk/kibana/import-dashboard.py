#!/usr/bin/env python3

import requests
import json
import time
import sys
import os

# Configuration
KIBANA_URL = "http://kibana:5601"
KIBANA_USER = "elastic"
KIBANA_PASS = os.getenv("ELASTIC_PASSWORD", "galah123")
DASHBOARD_FILE = "/usr/share/kibana/dashboards/galah-security-dashboard.ndjson"

def wait_for_kibana():
    """Wait for Kibana to be ready"""
    print("🍯 Waiting for Kibana to be ready...")
    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get(
                f"{KIBANA_URL}/api/status", 
                auth=(KIBANA_USER, KIBANA_PASS),
                timeout=10
            )
            if response.status_code == 200:
                status_data = response.json()
                if status_data.get("status", {}).get("overall", {}).get("level") == "available":
                    print("✅ Kibana is ready!")
                    return True
        except Exception as e:
            print(f"   Attempt {i+1}/{max_retries}: Kibana not ready yet ({e})")
        
        time.sleep(10)
    
    print("❌ Kibana failed to become ready")
    return False

def create_index_pattern():
    """Create the galah-events-* index pattern"""
    print("📊 Creating index pattern...")
    
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    
    index_pattern_data = {
        "attributes": {
            "title": "galah-events-*",
            "timeFieldName": "@timestamp"
        }
    }
    
    try:
        response = requests.post(
            f"{KIBANA_URL}/api/saved_objects/index-pattern/galah-events-*",
            auth=(KIBANA_USER, KIBANA_PASS),
            headers=headers,
            json=index_pattern_data
        )
        
        if response.status_code in [200, 409]:  # 409 = already exists
            print("✅ Index pattern created/exists")
            return True
        else:
            print(f"⚠️  Index pattern response: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Failed to create index pattern: {e}")
        return False

def import_dashboard():
    """Import the dashboard from NDJSON file"""
    print("📈 Importing dashboard...")
    
    if not os.path.exists(DASHBOARD_FILE):
        print(f"❌ Dashboard file not found: {DASHBOARD_FILE}")
        return False
    
    headers = {
        "kbn-xsrf": "true"
    }
    
    try:
        with open(DASHBOARD_FILE, 'rb') as f:
            files = {
                'file': ('galah-security-dashboard.ndjson', f, 'application/json')
            }
            
            response = requests.post(
                f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true",
                auth=(KIBANA_USER, KIBANA_PASS),
                headers=headers,
                files=files
            )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                print("✅ Dashboard imported successfully!")
                print(f"🌐 Access dashboard at: {KIBANA_URL}/app/dashboards#/view/galah-security-dashboard")
                return True
            else:
                print(f"⚠️  Import response: {result}")
                return False
        else:
            print(f"❌ Import failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to import dashboard: {e}")
        return False

def main():
    print("🍯 Galah Honeypot Dashboard Auto-Import")
    print("=" * 50)
    
    # Wait for Kibana to be ready
    if not wait_for_kibana():
        sys.exit(1)
    
    # Small delay to ensure full readiness
    time.sleep(5)
    
    # Create index pattern
    if not create_index_pattern():
        print("⚠️  Index pattern creation failed, but continuing...")
    
    # Import dashboard
    if not import_dashboard():
        sys.exit(1)
    
    print("🎯 Dashboard setup complete!")
    print(f"🔑 Login: {KIBANA_USER} / {KIBANA_PASS}")

if __name__ == "__main__":
    main()