#!/usr/bin/env python3
"""
Collect botnet C2 IPs from Feodo Tracker (abuse.ch)
No API key required - public feed
Tracks: Dridex, Emotet, TrickBot, QakBot, BazarLoader
"""

import os
import json
import requests
from datetime import datetime

OUTPUT_FILE = 'feeds/feodo-c2.json'

def collect_c2_ips():
    """Get active botnet C2 IPs"""
    
    url = 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json'
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        c2_ips = []
        for item in data:
            c2_ips.append({
                'ip': item.get('ip_address'),
                'port': item.get('port'),
                'malware': item.get('malware'),
                'first_seen': item.get('first_seen'),
                'last_online': item.get('last_online'),
                'source': 'feodo_tracker',
                'threat_type': 'botnet_c2'
            })
        
        print(f"Collected {len(c2_ips)} botnet C2 IPs from Feodo Tracker")
        return c2_ips
        
    except Exception as e:
        print(f"ERROR collecting Feodo Tracker: {e}")
        return []

def save_feeds(c2_ips):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'feodo_tracker',
            'updated': datetime.utcnow().isoformat(),
            'count': len(c2_ips),
            'description': 'Botnet C2 servers (Dridex, Emotet, TrickBot, QakBot)',
            'data': c2_ips
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    c2_ips = collect_c2_ips()
    if c2_ips:
        save_feeds(c2_ips)
