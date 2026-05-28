"""
MITRE ATT&CK Framework Database
Complete mapping of tactics, techniques, and attack patterns
"""

class MitreDatabase:
    """MITRE ATT&CK Framework Database"""
    
    # MITRE ATT&CK Tactics
    TACTICS = {
        'reconnaissance': {
            'id': 'TA0043',
            'name': 'Reconnaissance',
            'description': 'Gather information used to plan future operations'
        },
        'resource_development': {
            'id': 'TA0042',
            'name': 'Resource Development',
            'description': 'Establish resources for conducting operations'
        },
        'initial_access': {
            'id': 'TA0001',
            'name': 'Initial Access',
            'description': 'Techniques used to gain initial foothold'
        },
        'execution': {
            'id': 'TA0002',
            'name': 'Execution',
            'description': 'Techniques to execute code or commands'
        },
        'persistence': {
            'id': 'TA0003',
            'name': 'Persistence',
            'description': 'Techniques to maintain access'
        },
        'privilege_escalation': {
            'id': 'TA0004',
            'name': 'Privilege Escalation',
            'description': 'Techniques to gain higher-level permissions'
        },
        'defense_evasion': {
            'id': 'TA0005',
            'name': 'Defense Evasion',
            'description': 'Techniques to evade defenses'
        },
        'credential_access': {
            'id': 'TA0006',
            'name': 'Credential Access',
            'description': 'Techniques to steal credentials'
        },
        'discovery': {
            'id': 'TA0007',
            'name': 'Discovery',
            'description': 'Techniques to gather system information'
        },
        'lateral_movement': {
            'id': 'TA0008',
            'name': 'Lateral Movement',
            'description': 'Techniques to move through network'
        },
        'collection': {
            'id': 'TA0009',
            'name': 'Collection',
            'description': 'Techniques to gather data'
        },
        'exfiltration': {
            'id': 'TA0010',
            'name': 'Exfiltration',
            'description': 'Techniques to steal data'
        },
        'command_control': {
            'id': 'TA0011',
            'name': 'Command and Control',
            'description': 'Techniques to communicate with compromised systems'
        },
        'impact': {
            'id': 'TA0040',
            'name': 'Impact',
            'description': 'Techniques to disrupt operations'
        }
    }
    
    # MITRE ATT&CK Techniques (subset for common attacks)
    TECHNIQUES = {
        'T1595': {
            'id': 'T1595',
            'name': 'Active Scanning',
            'tactic': 'reconnaissance',
            'description': 'Probing for vulnerabilities'
        },
        'T1592': {
            'id': 'T1592',
            'name': 'Gather Victim Host Information',
            'tactic': 'reconnaissance',
            'description': 'Collecting information about target systems'
        },
        'T1190': {
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'tactic': 'initial_access',
            'description': 'Exploiting vulnerabilities in web applications'
        },
        'T1200': {
            'id': 'T1200',
            'name': 'Hardware Additions',
            'tactic': 'initial_access',
            'description': 'Adding malicious hardware'
        },
        'T1566': {
            'id': 'T1566',
            'name': 'Phishing',
            'tactic': 'initial_access',
            'description': 'Sending deceptive communications'
        },
        'T1059': {
            'id': 'T1059',
            'name': 'Command and Scripting Interpreter',
            'tactic': 'execution',
            'description': 'Executing commands via shell/script'
        },
        'T1203': {
            'id': 'T1203',
            'name': 'Exploitation for Client Execution',
            'tactic': 'execution',
            'description': 'Exploiting client vulnerabilities'
        },
        'T1110': {
            'id': 'T1110',
            'name': 'Brute Force',
            'tactic': 'credential_access',
            'description': 'Attempting multiple password combinations'
        },
        'T1555': {
            'id': 'T1555',
            'name': 'Credentials from Password Managers',
            'tactic': 'credential_access',
            'description': 'Stealing credentials from password managers'
        },
        'T1557': {
            'id': 'T1557',
            'name': 'Man-in-the-Middle',
            'tactic': 'credential_access',
            'description': 'Intercepting communications'
        },
        'T1087': {
            'id': 'T1087',
            'name': 'Account Discovery',
            'tactic': 'discovery',
            'description': 'Enumerating user accounts'
        },
        'T1526': {
            'id': 'T1526',
            'name': 'Cloud Service Discovery',
            'tactic': 'discovery',
            'description': 'Discovering cloud services'
        },
        'T1046': {
            'id': 'T1046',
            'name': 'Network Service Discovery',
            'tactic': 'discovery',
            'description': 'Scanning for network services'
        },
        'T1021': {
            'id': 'T1021',
            'name': 'Remote Services',
            'tactic': 'lateral_movement',
            'description': 'Using remote services for lateral movement'
        },
        'T1570': {
            'id': 'T1570',
            'name': 'Lateral Tool Transfer',
            'tactic': 'lateral_movement',
            'description': 'Transferring tools between systems'
        },
        'T1005': {
            'id': 'T1005',
            'name': 'Data from Local System',
            'tactic': 'collection',
            'description': 'Collecting data from local systems'
        },
        'T1041': {
            'id': 'T1041',
            'name': 'Exfiltration Over C2 Channel',
            'tactic': 'exfiltration',
            'description': 'Stealing data via command and control'
        },
        'T1048': {
            'id': 'T1048',
            'name': 'Exfiltration Over Alternative Protocol',
            'tactic': 'exfiltration',
            'description': 'Stealing data via alternative protocols'
        },
        'T1071': {
            'id': 'T1071',
            'name': 'Application Layer Protocol',
            'tactic': 'command_control',
            'description': 'Using application protocols for C2'
        },
        'T1095': {
            'id': 'T1095',
            'name': 'Non-Application Layer Protocol',
            'tactic': 'command_control',
            'description': 'Using non-standard protocols for C2'
        },
        'T1561': {
            'id': 'T1561',
            'name': 'Disk Wipe',
            'tactic': 'impact',
            'description': 'Wiping disk contents'
        },
        'T1499': {
            'id': 'T1499',
            'name': 'Endpoint Denial of Service',
            'tactic': 'impact',
            'description': 'DoS attacks on endpoints'
        }
    }
    
    # Attack Type to MITRE Mapping
    ATTACK_MAPPING = {
        'Fuzzers': {
            'tactics': ['initial_access', 'execution'],
            'techniques': ['T1190', 'T1203'],
            'description': 'Fuzzing attacks to find vulnerabilities'
        },
        'Analysis': {
            'tactics': ['reconnaissance', 'discovery'],
            'techniques': ['T1595', 'T1046', 'T1087'],
            'description': 'Network analysis and reconnaissance'
        },
        'Backdoor': {
            'tactics': ['persistence', 'command_control'],
            'techniques': ['T1071', 'T1095'],
            'description': 'Backdoor installation and C2 communication'
        },
        'DoS': {
            'tactics': ['impact'],
            'techniques': ['T1499'],
            'description': 'Denial of Service attacks'
        },
        'Exploits': {
            'tactics': ['initial_access', 'execution', 'privilege_escalation'],
            'techniques': ['T1190', 'T1203', 'T1059'],
            'description': 'Exploitation of known vulnerabilities'
        },
        'Generic': {
            'tactics': ['reconnaissance'],
            'techniques': ['T1595'],
            'description': 'Generic attack patterns'
        },
        'Reconnaissance': {
            'tactics': ['reconnaissance', 'discovery'],
            'techniques': ['T1595', 'T1592', 'T1046'],
            'description': 'Reconnaissance and scanning activities'
        },
        'Shellcode': {
            'tactics': ['execution', 'defense_evasion'],
            'techniques': ['T1059', 'T1203'],
            'description': 'Shellcode injection and execution'
        },
        'Worms': {
            'tactics': ['execution', 'lateral_movement', 'persistence'],
            'techniques': ['T1059', 'T1021', 'T1570'],
            'description': 'Self-propagating malware'
        }
    }
    
    @classmethod
    def get_tactic(cls, tactic_key):
        """Get tactic details"""
        return cls.TACTICS.get(tactic_key)
    
    @classmethod
    def get_technique(cls, technique_id):
        """Get technique details"""
        return cls.TECHNIQUES.get(technique_id)
    
    @classmethod
    def get_attack_mapping(cls, attack_type):
        """Get MITRE mapping for attack type"""
        return cls.ATTACK_MAPPING.get(attack_type)
    
    @classmethod
    def get_all_tactics(cls):
        """Get all tactics"""
        return cls.TACTICS
    
    @classmethod
    def get_all_techniques(cls):
        """Get all techniques"""
        return cls.TECHNIQUES
    
    @classmethod
    def get_all_mappings(cls):
        """Get all attack mappings"""
        return cls.ATTACK_MAPPING
    
    @classmethod
    def search_by_tactic(cls, tactic_key):
        """Find all techniques for a tactic"""
        techniques = []
        for tech_id, tech_data in cls.TECHNIQUES.items():
            if tech_data['tactic'] == tactic_key:
                techniques.append(tech_data)
        return techniques
    
    @classmethod
    def search_by_keyword(cls, keyword):
        """Search techniques by keyword"""
        results = []
        keyword_lower = keyword.lower()
        
        for tech_id, tech_data in cls.TECHNIQUES.items():
            if (keyword_lower in tech_data['name'].lower() or
                keyword_lower in tech_data['description'].lower()):
                results.append(tech_data)
        
        return results
