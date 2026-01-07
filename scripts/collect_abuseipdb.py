#!/usr/bin/env python3
"""
Collect top reported IPs from AbuseIPDB
Free tier: 1,000 requests/day
"""

import os
import json
import requests
import yaml
from datetime import datetime

API_KEY = os.environ.get('ABUSEIPDB_KEY')
OUTPUT_FILE = 'feeds/abuseipdb-ips.json'

def collect_blacklist():
    """Get the AbuseIPDB blacklist (top 10,000 most reported IPs)"""
    
    if not API_KEY:
        print("WARNING: ABUSEIPDB_KEY not set, skipping...")
        return []
    
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    params = {
        'confidenceMinimum': 75,  # Only high-confidence reports
        'limit': 10000
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        ips = []
        for item in data.get('data', []):
            ips.append({
                'ip': item['ipAddress'],
                'score': item['abuseConfidenceScore'],
                'country': item.get('countryCode', 'XX'),
                'source': 'abuseipdb',
                'last_seen': datetime.utcnow().isoformat()
            })
        
        print(f"Collected {len(ips)} IPs from AbuseIPDB")
        return ips
        
    except Exception as e:
        print(f"ERROR collecting AbuseIPDB: {e}")
        return []

def save_feeds(ips):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'abuseipdb',
            'updated': datetime.utcnow().isoformat(),
            'count': len(ips),
            'data': ips
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    ips = collect_blacklist()
    if ips:
        save_feeds(ips)
