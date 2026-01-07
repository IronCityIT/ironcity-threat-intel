#!/usr/bin/env python3
"""
Collect scanner/noise IPs from GreyNoise
Free tier: 10,000 requests/month
"""

import os
import json
import requests
from datetime import datetime

API_KEY = os.environ.get('GREYNOISE_KEY')
OUTPUT_FILE = 'feeds/greynoise-scanners.json'

def collect_riot_ips():
    """Get known benign scanner IPs (to whitelist, not block)"""
    
    if not API_KEY:
        print("WARNING: GREYNOISE_KEY not set, skipping...")
        return {'malicious': [], 'benign': []}
    
    headers = {
        'Accept': 'application/json',
        'key': API_KEY
    }
    
    malicious = []
    benign = []
    
    try:
        # Query for malicious scanners
        url = 'https://api.greynoise.io/v2/experimental/gnql'
        params = {'query': 'classification:malicious last_seen:1d', 'size': 1000}
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            for item in data.get('data', []):
                malicious.append({
                    'ip': item.get('ip'),
                    'classification': 'malicious',
                    'name': item.get('actor', 'unknown'),
                    'tags': item.get('tags', []),
                    'source': 'greynoise',
                    'last_seen': item.get('last_seen')
                })
        
        # Query for benign scanners (useful for whitelisting Shodan, etc)
        params = {'query': 'classification:benign last_seen:1d', 'size': 500}
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            for item in data.get('data', []):
                benign.append({
                    'ip': item.get('ip'),
                    'classification': 'benign',
                    'name': item.get('actor', 'unknown'),
                    'tags': item.get('tags', []),
                    'source': 'greynoise',
                    'last_seen': item.get('last_seen')
                })
        
        print(f"Collected from GreyNoise: {len(malicious)} malicious, {len(benign)} benign scanners")
        return {'malicious': malicious, 'benign': benign}
        
    except Exception as e:
        print(f"ERROR collecting GreyNoise: {e}")
        return {'malicious': [], 'benign': []}

def save_feeds(data):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'greynoise',
            'updated': datetime.utcnow().isoformat(),
            'counts': {
                'malicious': len(data['malicious']),
                'benign': len(data['benign'])
            },
            'data': data
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    scanners = collect_riot_ips()
    save_feeds(scanners)
