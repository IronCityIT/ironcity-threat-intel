#!/usr/bin/env python3
"""
Merge all threat intel feeds into Logstash-ready YAML format
Creates lookup files for the translate filter
"""

import os
import json
import yaml
from datetime import datetime

FEEDS_DIR = 'feeds'
OUTPUT_DIR = 'feeds'

def load_json(filename):
    """Load JSON feed file"""
    filepath = os.path.join(FEEDS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

def merge_malicious_ips():
    """Combine all malicious IPs into single lookup file"""
    
    all_ips = {}
    
    # AbuseIPDB
    data = load_json('abuseipdb-ips.json')
    if data:
        for item in data.get('data', []):
            ip = item.get('ip')
            if ip:
                all_ips[ip] = f"malicious|abuseipdb|score:{item.get('score', 0)}|country:{item.get('country', 'XX')}"
    
    # AlienVault
    data = load_json('alienvault-indicators.json')
    if data:
        for item in data.get('data', {}).get('ips', []):
            ip = item.get('value')
            if ip and ip not in all_ips:
                tags = ','.join(item.get('tags', [])[:3])  # First 3 tags
                all_ips[ip] = f"malicious|alienvault|pulse:{item.get('pulse', 'unknown')[:30]}|tags:{tags}"
    
    # GreyNoise malicious
    data = load_json('greynoise-scanners.json')
    if data:
        for item in data.get('data', {}).get('malicious', []):
            ip = item.get('ip')
            if ip and ip not in all_ips:
                all_ips[ip] = f"scanner|greynoise|actor:{item.get('name', 'unknown')}|classification:malicious"
    
    # Feodo C2
    data = load_json('feodo-c2.json')
    if data:
        for item in data.get('data', []):
            ip = item.get('ip')
            if ip:
                # C2 servers are high priority - overwrite if exists
                all_ips[ip] = f"botnet_c2|feodo|malware:{item.get('malware', 'unknown')}|port:{item.get('port', 'unknown')}"
    
    # Spamhaus (CIDR ranges - just use first IP for now, full implementation would need IP range matching)
    data = load_json('spamhaus-drop.json')
    if data:
        for item in data.get('data', []):
            cidr = item.get('cidr', '')
            if '/' in cidr:
                # Extract base IP from CIDR
                base_ip = cidr.split('/')[0]
                if base_ip and base_ip not in all_ips:
                    all_ips[base_ip] = f"spam_botnet|spamhaus|cidr:{cidr}|ref:{item.get('reference', 'unknown')}"
    
    print(f"Total unique malicious IPs: {len(all_ips)}")
    return all_ips

def merge_malicious_domains():
    """Combine all malicious domains into single lookup file"""
    
    all_domains = {}
    
    # AlienVault domains
    data = load_json('alienvault-indicators.json')
    if data:
        for item in data.get('data', {}).get('domains', []):
            domain = item.get('value')
            if domain:
                all_domains[domain] = f"malicious|alienvault|pulse:{item.get('pulse', 'unknown')[:30]}"
    
    # URLhaus hosts
    data = load_json('urlhaus-malware.json')
    if data:
        for item in data.get('data', {}).get('urls', []):
            host = item.get('host')
            if host and host not in all_domains:
                threat = item.get('threat', 'malware')
                all_domains[host] = f"malware|urlhaus|threat:{threat}"
    
    print(f"Total unique malicious domains: {len(all_domains)}")
    return all_domains

def merge_malicious_hashes():
    """Combine all malicious file hashes"""
    
    all_hashes = {}
    
    # AlienVault hashes
    data = load_json('alienvault-indicators.json')
    if data:
        for item in data.get('data', {}).get('hashes', []):
            hash_val = item.get('value')
            if hash_val:
                all_hashes[hash_val.lower()] = f"malware|alienvault|type:{item.get('hash_type', 'unknown')}"
    
    # URLhaus payloads
    data = load_json('urlhaus-malware.json')
    if data:
        for item in data.get('data', {}).get('payloads', []):
            sha256 = item.get('sha256')
            if sha256:
                sig = item.get('signature', 'unknown')
                all_hashes[sha256.lower()] = f"malware|urlhaus|signature:{sig}|type:{item.get('file_type', 'unknown')}"
            
            md5 = item.get('md5')
            if md5 and md5.lower() not in all_hashes:
                all_hashes[md5.lower()] = f"malware|urlhaus|signature:{sig}"
    
    print(f"Total unique malicious hashes: {len(all_hashes)}")
    return all_hashes

def merge_benign_scanners():
    """Get benign scanner IPs for whitelisting"""
    
    benign = {}
    
    data = load_json('greynoise-scanners.json')
    if data:
        for item in data.get('data', {}).get('benign', []):
            ip = item.get('ip')
            if ip:
                benign[ip] = f"benign|greynoise|actor:{item.get('name', 'unknown')}"
    
    print(f"Total benign scanner IPs: {len(benign)}")
    return benign

def save_yaml(data, filename):
    """Save as YAML for Logstash translate filter"""
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, 'w') as f:
        f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
        f.write(f"# Count: {len(data)}\n")
        f.write("# Format: indicator: \"type|source|metadata\"\n\n")
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    
    print(f"Saved {filename} ({len(data)} entries)")

def create_summary():
    """Create summary file with stats"""
    
    summary = {
        'generated': datetime.utcnow().isoformat(),
        'feeds': {}
    }
    
    for filename in os.listdir(FEEDS_DIR):
        if filename.endswith('.json'):
            data = load_json(filename)
            if data:
                summary['feeds'][filename] = {
                    'source': data.get('source'),
                    'updated': data.get('updated'),
                    'count': data.get('count') or data.get('counts')
                }
    
    with open(os.path.join(OUTPUT_DIR, 'feed-summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\nFeed Summary:")
    for feed, info in summary['feeds'].items():
        print(f"  {feed}: {info.get('count')} items")

if __name__ == '__main__':
    print("=" * 50)
    print("Merging threat intel feeds for Logstash")
    print("=" * 50)
    
    # Merge and save
    malicious_ips = merge_malicious_ips()
    save_yaml(malicious_ips, 'malicious-ips.yml')
    
    malicious_domains = merge_malicious_domains()
    save_yaml(malicious_domains, 'malicious-domains.yml')
    
    malicious_hashes = merge_malicious_hashes()
    save_yaml(malicious_hashes, 'malicious-hashes.yml')
    
    benign_scanners = merge_benign_scanners()
    save_yaml(benign_scanners, 'benign-scanners.yml')
    
    create_summary()
    
    print("\n" + "=" * 50)
    print("Done! Files ready for Logstash deployment")
    print("=" * 50)
