"""
MITRE ATT&CK Mapper
Maps attack patterns to MITRE tactics and techniques
"""

from .mitre_database import MitreDatabase
import json
from datetime import datetime

class MitreMapper:
    """Map attacks to MITRE ATT&CK framework"""
    
    def __init__(self):
        self.db = MitreDatabase()
    
    def map_attack(self, attack_type, attack_data=None):
        """
        Map attack to MITRE tactics and techniques
        
        Args:
            attack_type: Type of attack (e.g., 'Exploits', 'DoS')
            attack_data: Additional attack information
        
        Returns:
            Dictionary with MITRE mapping
        """
        mapping = self.db.get_attack_mapping(attack_type)
        
        if not mapping:
            return {
                'attack_type': attack_type,
                'found': False,
                'tactics': [],
                'techniques': []
            }
        
        # Get full tactic and technique details
        tactics = []
        for tactic_key in mapping['tactics']:
            tactic = self.db.get_tactic(tactic_key)
            if tactic:
                tactics.append(tactic)
        
        techniques = []
        for tech_id in mapping['techniques']:
            technique = self.db.get_technique(tech_id)
            if technique:
                techniques.append(technique)
        
        return {
            'attack_type': attack_type,
            'found': True,
            'description': mapping['description'],
            'tactics': tactics,
            'techniques': techniques,
            'mapped_at': datetime.now().isoformat()
        }
    
    def map_ssh_attack(self, ssh_data):
        """
        Map SSH attack to MITRE framework
        
        Args:
            ssh_data: SSH attack data
        
        Returns:
            MITRE mapping for SSH attack
        """
        attack_type = 'Reconnaissance'
        
        # Check for brute force
        if ssh_data.get('failed_attempts', 0) > 5:
            attack_type = 'Credential Access'
            mapping = self.db.get_attack_mapping('Fuzzers')
            if not mapping:
                mapping = {
                    'tactics': ['credential_access'],
                    'techniques': ['T1110'],
                    'description': 'SSH Brute Force Attack'
                }
        else:
            mapping = self.db.get_attack_mapping(attack_type)
        
        return {
            'source': 'SSH',
            'attack_type': attack_type,
            'source_ip': ssh_data.get('source_ip'),
            'username': ssh_data.get('username'),
            'failed_attempts': ssh_data.get('failed_attempts', 0),
            'mitre_mapping': mapping
        }
    
    def map_http_attack(self, http_data):
        """
        Map HTTP attack to MITRE framework
        
        Args:
            http_data: HTTP attack data
        
        Returns:
            MITRE mapping for HTTP attack
        """
        attack_type = 'Reconnaissance'
        
        # Detect attack type from HTTP payload
        payload = http_data.get('payload', '').lower()
        
        if 'union' in payload or 'select' in payload or 'drop' in payload:
            attack_type = 'Exploits'
        elif '<script>' in payload or 'javascript:' in payload:
            attack_type = 'Fuzzers'
        elif '../' in payload or '..\\' in payload:
            attack_type = 'Exploits'
        
        mapping = self.db.get_attack_mapping(attack_type)
        
        return {
            'source': 'HTTP',
            'attack_type': attack_type,
            'source_ip': http_data.get('source_ip'),
            'method': http_data.get('method'),
            'path': http_data.get('path'),
            'payload': http_data.get('payload'),
            'mitre_mapping': mapping
        }
    
    def get_tactic_info(self, tactic_key):
        """Get detailed tactic information"""
        tactic = self.db.get_tactic(tactic_key)
        
        if not tactic:
            return None
        
        # Get all techniques for this tactic
        techniques = self.db.search_by_tactic(tactic_key)
        
        return {
            'tactic': tactic,
            'techniques': techniques,
            'technique_count': len(techniques)
        }
    
    def get_technique_info(self, technique_id):
        """Get detailed technique information"""
        technique = self.db.get_technique(technique_id)
        
        if not technique:
            return None
        
        # Get tactic for this technique
        tactic = self.db.get_tactic(technique['tactic'])
        
        return {
            'technique': technique,
            'tactic': tactic
        }
    
    def search_techniques(self, keyword):
        """Search techniques by keyword"""
        return self.db.search_by_keyword(keyword)
    
    def generate_report(self, attack_list):
        """
        Generate MITRE ATT&CK report for multiple attacks
        
        Args:
            attack_list: List of attacks
        
        Returns:
            Comprehensive MITRE report
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_attacks': len(attack_list),
            'tactics_used': {},
            'techniques_used': {},
            'attack_types': {},
            'attacks': []
        }
        
        for attack in attack_list:
            attack_type = attack.get('type', 'Unknown')
            mapping = self.map_attack(attack_type, attack)
            
            # Add to report
            report['attacks'].append({
                'attack': attack,
                'mitre_mapping': mapping
            })
            
            # Aggregate tactics
            for tactic in mapping.get('tactics', []):
                tactic_id = tactic.get('id')
                if tactic_id not in report['tactics_used']:
                    report['tactics_used'][tactic_id] = {
                        'tactic': tactic,
                        'count': 0
                    }
                report['tactics_used'][tactic_id]['count'] += 1
            
            # Aggregate techniques
            for technique in mapping.get('techniques', []):
                tech_id = technique.get('id')
                if tech_id not in report['techniques_used']:
                    report['techniques_used'][tech_id] = {
                        'technique': technique,
                        'count': 0
                    }
                report['techniques_used'][tech_id]['count'] += 1
            
            # Aggregate attack types
            if attack_type not in report['attack_types']:
                report['attack_types'][attack_type] = 0
            report['attack_types'][attack_type] += 1
        
        return report
    
    def export_report(self, report, output_file='mitre_report.json'):
        """Export MITRE report to JSON"""
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_file

# Singleton instance
mapper = MitreMapper()
