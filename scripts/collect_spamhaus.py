#!/usr/bin/env python3
"""
Collect Spamhaus DROP/EDROP lists
No API key required - public lists
"""

import os
import json
import requests
from datetime import datetime

OUTPUT_FILE = 'feeds/spamhaus-drop.json'

FEEDS = {
    'drop': 'https://www.spamhaus.org/drop/drop.txt',
    'edrop': 'https://www.spamhaus.org/drop/edrop.txt',
    'dropv6': 'https://www.spamhaus.org/drop/dropv6.txt'
}

def collect_drop_lists():
    """Download Spamhaus DROP lists"""
    
    all_ranges = []
    
    for feed_name, url in FEEDS.items():
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith(';'):
                    continue
                
                # Format: CIDR ; SBL reference
                parts = line.split(';')
                if len(parts) >= 1:
                    cidr = parts[0].strip()
                    sbl_ref = parts[1].strip() if len(parts) > 1 else 'unknown'
                    
                    all_ranges.append({
                        'cidr': cidr,
                        'reference': sbl_ref,
                        'feed': feed_name,
                        'source': 'spamhaus',
                        'threat_type': 'spam_botnet'
                    })
            
            print(f"Collected {feed_name}: {len([r for r in all_ranges if r['feed'] == feed_name])} ranges")
            
        except Exception as e:
            print(f"ERROR collecting {feed_name}: {e}")
    
    print(f"Total Spamhaus ranges: {len(all_ranges)}")
    return all_ranges

def save_feeds(ranges):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'spamhaus',
            'updated': datetime.utcnow().isoformat(),
            'count': len(ranges),
            'data': ranges
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    ranges = collect_drop_lists()
    if ranges:
        save_feeds(ranges)
