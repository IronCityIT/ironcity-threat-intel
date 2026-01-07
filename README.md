# Iron City IT - Threat Intelligence Feeds

Automated threat intelligence collection for ICIT Sentinel SIEM.

## Overview

This repository automatically collects threat intelligence from multiple free sources and deploys them to the Wazuh/Logstash server for real-time enrichment.

## Sources

| Source | Type | API Key Required | Rate Limit |
|--------|------|------------------|------------|
| AbuseIPDB | IP Reputation | Yes | 1,000/day |
| AlienVault OTX | Multi-IOC | Yes | Unlimited |
| GreyNoise | Scanner Detection | Yes | 10,000/month |
| Spamhaus DROP | IP Ranges | No | Public |
| URLhaus | Malware URLs | No | Public |
| Feodo Tracker | Botnet C2 | No | Public |

## Output Files

The workflow generates these Logstash-ready YAML files:

- `malicious-ips.yml` - Combined malicious IP addresses
- `malicious-domains.yml` - Known malicious domains
- `malicious-hashes.yml` - Malware file hashes (MD5, SHA256)
- `benign-scanners.yml` - Known good scanners (for whitelisting)

## Schedule

The GitHub Action runs every 6 hours and deploys to the Wazuh server automatically.

## Setup

### Required GitHub Secrets

```
ABUSEIPDB_KEY     - AbuseIPDB API key
ALIENVAULT_KEY    - AlienVault OTX API key  
GREYNOISE_KEY     - GreyNoise API key
WAZUH_HOST        - Wazuh server IP/hostname
WAZUH_USER        - SSH username (usually root)
WAZUH_SSH_KEY     - Private SSH key for deployment
```

### Manual Trigger

You can manually trigger the workflow from the Actions tab in GitHub.

## Logstash Integration

The translate filter uses these files:

```ruby
translate {
  field => "[data][srcip]"
  destination => "[threat_intel][ip_reputation]"
  dictionary_path => "/etc/logstash/threat-intel/malicious-ips.yml"
  fallback => "unknown"
  refresh_interval => 300
}
```

## License

Internal use only - Iron City IT Advisors LLC

## Contact

security@ironcityit.com
