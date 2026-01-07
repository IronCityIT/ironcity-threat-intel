#!/usr/bin/env python3
"""
Collect threat indicators from AlienVault OTX
Free tier: Unlimited (be nice, don't hammer)
"""

import os
import json
import requests
from datetime import datetime, timedelta

API_KEY = os.environ.get('ALIENVAULT_KEY')
OUTPUT_FILE = 'feeds/alienvault-indicators.json'

def collect_pulses():
    """Get recent pulses with IOCs"""
    
    if not API_KEY:
        print("WARNING: ALIENVAULT_KEY not set, skipping...")
        return {'ips': [], 'domains': [], 'hashes': []}
    
    headers = {'X-OTX-API-KEY': API_KEY}
    
    # Get pulses modified in last 7 days
    since = (datetime.utcnow() - timedelta(days=7)).isoformat()
    url = f'https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}&limit=50'
    
    ips = []
    domains = []
    hashes = []
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        for pulse in data.get('results', []):
            pulse_name = pulse.get('name', 'Unknown')
            pulse_tags = pulse.get('tags', [])
            
            for indicator in pulse.get('indicators', []):
                ioc_type = indicator.get('type')
                ioc_value = indicator.get('indicator')
                
                entry = {
                    'value': ioc_value,
                    'pulse': pulse_name,
                    'tags': pulse_tags,
                    'source': 'alienvault_otx',
                    'created': indicator.get('created')
                }
                
                if ioc_type == 'IPv4':
                    ips.append(entry)
                elif ioc_type in ['domain', 'hostname']:
                    domains.append(entry)
                elif ioc_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                    entry['hash_type'] = ioc_type.replace('FileHash-', '').lower()
                    hashes.append(entry)
        
        print(f"Collected from AlienVault: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes")
        return {'ips': ips, 'domains': domains, 'hashes': hashes}
        
    except Exception as e:
        print(f"ERROR collecting AlienVault: {e}")
        return {'ips': [], 'domains': [], 'hashes': []}

def save_feeds(data):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'alienvault_otx',
            'updated': datetime.utcnow().isoformat(),
            'counts': {
                'ips': len(data['ips']),
                'domains': len(data['domains']),
                'hashes': len(data['hashes'])
            },
            'data': data
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    indicators = collect_pulses()
    save_feeds(indicators)
