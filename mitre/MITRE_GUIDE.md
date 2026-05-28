# MITRE ATT&CK Integration Guide

Complete guide for using MITRE ATT&CK framework in HoneyTrack.

## Overview

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. HoneyTrack integrates this framework to classify and understand attacks.

## Quick Start

### Basic Usage

```python
from mitre.mitre_mapper import mapper

# Map an attack type
mapping = mapper.map_attack('Exploits')
print(mapping)
# Output:
# {
#     'attack_type': 'Exploits',
#     'found': True,
#     'description': 'Exploitation of known vulnerabilities',
#     'tactics': [
#         {'id': 'TA0001', 'name': 'Initial Access', ...},
#         {'id': 'TA0002', 'name': 'Execution', ...},
#         {'id': 'TA0004', 'name': 'Privilege Escalation', ...}
#     ],
#     'techniques': [
#         {'id': 'T1190', 'name': 'Exploit Public-Facing Application', ...},
#         {'id': 'T1203', 'name': 'Exploitation for Client Execution', ...},
#         {'id': 'T1059', 'name': 'Command and Scripting Interpreter', ...}
#     ]
# }
```

### Map SSH Attacks

```python
from mitre.mitre_mapper import mapper

ssh_data = {
    'source_ip': '192.168.1.100',
    'username': 'admin',
    'failed_attempts': 10
}

mapping = mapper.map_ssh_attack(ssh_data)
print(mapping)
# Output:
# {
#     'source': 'SSH',
#     'attack_type': 'Credential Access',
#     'source_ip': '192.168.1.100',
#     'username': 'admin',
#     'failed_attempts': 10,
#     'mitre_mapping': {
#         'tactics': ['credential_access'],
#         'techniques': ['T1110'],
#         'description': 'SSH Brute Force Attack'
#     }
# }
```

### Map HTTP Attacks

```python
from mitre.mitre_mapper import mapper

http_data = {
    'source_ip': '10.0.0.50',
    'method': 'GET',
    'path': '/search.php',
    'payload': "id=1 UNION SELECT * FROM users--"
}

mapping = mapper.map_http_attack(http_data)
print(mapping)
# Output:
# {
#     'source': 'HTTP',
#     'attack_type': 'Exploits',
#     'source_ip': '10.0.0.50',
#     'method': 'GET',
#     'path': '/search.php',
#     'payload': "id=1 UNION SELECT * FROM users--",
#     'mitre_mapping': {
#         'tactics': ['initial_access', 'execution', 'privilege_escalation'],
#         'techniques': ['T1190', 'T1203', 'T1059'],
#         'description': 'Exploitation of known vulnerabilities'
#     }
# }
```

## Tactics (14 Total)

| Tactic ID | Tactic Name | Description |
|-----------|-------------|-------------|
| TA0043 | Reconnaissance | Gather information used to plan future operations |
| TA0042 | Resource Development | Establish resources for conducting operations |
| TA0001 | Initial Access | Techniques used to gain initial foothold |
| TA0002 | Execution | Techniques to execute code or commands |
| TA0003 | Persistence | Techniques to maintain access |
| TA0004 | Privilege Escalation | Techniques to gain higher-level permissions |
| TA0005 | Defense Evasion | Techniques to evade defenses |
| TA0006 | Credential Access | Techniques to steal credentials |
| TA0007 | Discovery | Techniques to gather system information |
| TA0008 | Lateral Movement | Techniques to move through network |
| TA0009 | Collection | Techniques to gather data |
| TA0010 | Exfiltration | Techniques to steal data |
| TA0011 | Command and Control | Techniques to communicate with compromised systems |
| TA0040 | Impact | Techniques to disrupt operations |

## Techniques (20+ Included)

### Reconnaissance
- **T1595**: Active Scanning - Probing for vulnerabilities
- **T1592**: Gather Victim Host Information - Collecting system information

### Initial Access
- **T1190**: Exploit Public-Facing Application - Exploiting web vulnerabilities
- **T1200**: Hardware Additions - Adding malicious hardware
- **T1566**: Phishing - Sending deceptive communications

### Execution
- **T1059**: Command and Scripting Interpreter - Executing commands via shell
- **T1203**: Exploitation for Client Execution - Exploiting client vulnerabilities

### Credential Access
- **T1110**: Brute Force - Attempting multiple password combinations
- **T1555**: Credentials from Password Managers - Stealing credentials
- **T1557**: Man-in-the-Middle - Intercepting communications

### Discovery
- **T1087**: Account Discovery - Enumerating user accounts
- **T1526**: Cloud Service Discovery - Discovering cloud services
- **T1046**: Network Service Discovery - Scanning for network services

### Lateral Movement
- **T1021**: Remote Services - Using remote services for lateral movement
- **T1570**: Lateral Tool Transfer - Transferring tools between systems

### Collection
- **T1005**: Data from Local System - Collecting data from local systems

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel - Stealing data via C2
- **T1048**: Exfiltration Over Alternative Protocol - Stealing data via alternative protocols

### Command and Control
- **T1071**: Application Layer Protocol - Using application protocols for C2
- **T1095**: Non-Application Layer Protocol - Using non-standard protocols for C2

### Impact
- **T1561**: Disk Wipe - Wiping disk contents
- **T1499**: Endpoint Denial of Service - DoS attacks on endpoints

## Attack Type Mapping

### Fuzzers
- **Tactics**: Initial Access, Execution
- **Techniques**: T1190, T1203
- **Description**: Fuzzing attacks to find vulnerabilities

### Analysis
- **Tactics**: Reconnaissance, Discovery
- **Techniques**: T1595, T1046, T1087
- **Description**: Network analysis and reconnaissance

### Backdoor
- **Tactics**: Persistence, Command and Control
- **Techniques**: T1071, T1095
- **Description**: Backdoor installation and C2 communication

### DoS
- **Tactics**: Impact
- **Techniques**: T1499
- **Description**: Denial of Service attacks

### Exploits
- **Tactics**: Initial Access, Execution, Privilege Escalation
- **Techniques**: T1190, T1203, T1059
- **Description**: Exploitation of known vulnerabilities

### Generic
- **Tactics**: Reconnaissance
- **Techniques**: T1595
- **Description**: Generic attack patterns

### Reconnaissance
- **Tactics**: Reconnaissance, Discovery
- **Techniques**: T1595, T1592, T1046
- **Description**: Reconnaissance and scanning activities

### Shellcode
- **Tactics**: Execution, Defense Evasion
- **Techniques**: T1059, T1203
- **Description**: Shellcode injection and execution

### Worms
- **Tactics**: Execution, Lateral Movement, Persistence
- **Techniques**: T1059, T1021, T1570
- **Description**: Self-propagating malware

## Advanced Usage

### Get Tactic Information

```python
from mitre.mitre_mapper import mapper

tactic_info = mapper.get_tactic_info('credential_access')
print(tactic_info)
# Output:
# {
#     'tactic': {
#         'id': 'TA0006',
#         'name': 'Credential Access',
#         'description': 'Techniques to steal credentials'
#     },
#     'techniques': [
#         {'id': 'T1110', 'name': 'Brute Force', ...},
#         {'id': 'T1555', 'name': 'Credentials from Password Managers', ...},
#         {'id': 'T1557', 'name': 'Man-in-the-Middle', ...}
#     ],
#     'technique_count': 3
# }
```

### Get Technique Information

```python
from mitre.mitre_mapper import mapper

tech_info = mapper.get_technique_info('T1110')
print(tech_info)
# Output:
# {
#     'technique': {
#         'id': 'T1110',
#         'name': 'Brute Force',
#         'tactic': 'credential_access',
#         'description': 'Attempting multiple password combinations'
#     },
#     'tactic': {
#         'id': 'TA0006',
#         'name': 'Credential Access',
#         'description': 'Techniques to steal credentials'
#     }
# }
```

### Search Techniques

```python
from mitre.mitre_mapper import mapper

results = mapper.search_techniques('brute')
print(results)
# Output:
# [
#     {
#         'id': 'T1110',
#         'name': 'Brute Force',
#         'tactic': 'credential_access',
#         'description': 'Attempting multiple password combinations'
#     }
# ]
```

### Generate Report

```python
from mitre.mitre_mapper import mapper

attacks = [
    {'type': 'Exploits', 'source_ip': '192.168.1.1'},
    {'type': 'DoS', 'source_ip': '192.168.1.2'},
    {'type': 'Fuzzers', 'source_ip': '192.168.1.3'}
]

report = mapper.generate_report(attacks)
print(report)
# Output:
# {
#     'generated_at': '2026-04-19T14:30:00.123456',
#     'total_attacks': 3,
#     'tactics_used': {
#         'TA0001': {'tactic': {...}, 'count': 1},
#         'TA0002': {'tactic': {...}, 'count': 2},
#         ...
#     },
#     'techniques_used': {
#         'T1190': {'technique': {...}, 'count': 1},
#         'T1499': {'technique': {...}, 'count': 1},
#         ...
#     },
#     'attack_types': {
#         'Exploits': 1,
#         'DoS': 1,
#         'Fuzzers': 1
#     },
#     'attacks': [...]
# }
```

### Export Report

```python
from mitre.mitre_mapper import mapper

report = mapper.generate_report(attacks)
output_file = mapper.export_report(report, 'mitre_report.json')
print(f"Report saved to {output_file}")
```

## Integration with ML Predictor

```python
from ml.predictor import predictor
from mitre.mitre_mapper import mapper

# Get ML prediction
prediction = predictor.predict(features)

# Map to MITRE
mitre_mapping = mapper.map_attack(prediction['attack_type'])

# Combined result
result = {
    'ml_prediction': prediction,
    'mitre_mapping': mitre_mapping
}

print(result)
```

## Integration with Dashboard

The MITRE ATT&CK mapping is automatically displayed in the dashboard:

1. **Attack Details**: Shows MITRE tactics and techniques for each attack
2. **MITRE Framework Page**: Displays all tactics and techniques
3. **Reports**: Includes MITRE mapping in generated reports

## References

- **MITRE ATT&CK**: https://attack.mitre.org
- **Framework Documentation**: https://attack.mitre.org/docs/
- **Tactics**: https://attack.mitre.org/tactics/
- **Techniques**: https://attack.mitre.org/techniques/

## Updates

To update MITRE ATT&CK mappings:

1. Visit https://attack.mitre.org
2. Download the latest framework data
3. Update `mitre_database.py` with new tactics/techniques
4. Restart HoneyTrack

---

**Last Updated**: April 2026
**Version**: 1.0.0
