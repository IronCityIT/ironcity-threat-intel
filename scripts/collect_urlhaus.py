#!/usr/bin/env python3
"""
Collect malware URLs from URLhaus (abuse.ch)
No API key required - public feed
"""

import os
import json
import requests
from datetime import datetime

OUTPUT_FILE = 'feeds/urlhaus-malware.json'

def collect_recent_urls():
    """Get recent malware URLs from URLhaus"""
    
    url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/'
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        urls = []
        for item in data.get('urls', []):
            urls.append({
                'url': item.get('url'),
                'host': item.get('host'),
                'threat': item.get('threat'),
                'tags': item.get('tags', []),
                'url_status': item.get('url_status'),
                'date_added': item.get('date_added'),
                'source': 'urlhaus'
            })
        
        print(f"Collected {len(urls)} malware URLs from URLhaus")
        return urls
        
    except Exception as e:
        print(f"ERROR collecting URLhaus: {e}")
        return []

def collect_payloads():
    """Get recent malware payloads/hashes"""
    
    url = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/500/'
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        payloads = []
        for item in data.get('payloads', []):
            payloads.append({
                'sha256': item.get('sha256_hash'),
                'md5': item.get('md5_hash'),
                'file_type': item.get('file_type'),
                'signature': item.get('signature'),
                'firstseen': item.get('firstseen'),
                'source': 'urlhaus'
            })
        
        print(f"Collected {len(payloads)} malware payloads from URLhaus")
        return payloads
        
    except Exception as e:
        print(f"ERROR collecting URLhaus payloads: {e}")
        return []

def save_feeds(urls, payloads):
    """Save to JSON file"""
    os.makedirs('feeds', exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            'source': 'urlhaus',
            'updated': datetime.utcnow().isoformat(),
            'counts': {
                'urls': len(urls),
                'payloads': len(payloads)
            },
            'data': {
                'urls': urls,
                'payloads': payloads
            }
        }, f, indent=2)
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    urls = collect_recent_urls()
    payloads = collect_payloads()
    save_feeds(urls, payloads)
