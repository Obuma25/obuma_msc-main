import boto3
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class GuardDutyMonitor:
    def __init__(self, region: str = 'eu-west-2'):
        self.region = region
        self.client = boto3.client('guardduty', region_name=region)
        self.detector_id = self._get_detector_id()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        self.logger.info(f"GuardDuty Monitor initialized for region: {region}")
        self.logger.info(f"Detector ID: {self.detector_id}")
    
    def _get_detector_id(self) -> str:
        try:
            response = self.client.list_detectors()
            
            if not response['DetectorIds']:
                raise RuntimeError(
                    "GuardDuty not enabled in this account/region. "
                    "Enable GuardDuty in AWS Console before running tests."
                )
            
            return response['DetectorIds'][0]
            
        except Exception as e:
            self.logger.error(f"Failed to get GuardDuty detector ID: {e}")
            raise
    
    def monitor_findings(self, attack_start_time: datetime, 
                        duration_minutes: int = 30,
                        poll_interval_seconds: int = 60) -> List[Dict]:
        self.logger.info(f"Starting monitoring for {duration_minutes} minutes")
        self.logger.info(f"Attack start time: {attack_start_time.isoformat()}")
        
        findings_detected = []
        finding_ids_seen = set()
        monitoring_end_time = attack_start_time + timedelta(minutes=duration_minutes)
        poll_count = 0
        while datetime.now(timezone.utc) < monitoring_end_time:
            poll_count += 1
            try:
                attack_start_ms = int(attack_start_time.timestamp() * 1000)
                response = self.client.list_findings(
                    DetectorId=self.detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'updatedAt': {
                                'Gte': attack_start_ms
                            },
                            'service.archived': {
                                'Eq': ['false']
                            }
                        }
                    },
                    MaxResults=50
                )
                
                if response['FindingIds']:
                    new_findings = [fid for fid in response['FindingIds'] if fid not in finding_ids_seen]
                    if new_findings:
                        finding_details = self.client.get_findings(
                            DetectorId=self.detector_id,
                            FindingIds=new_findings
                        )
                        
                        for finding in finding_details['Findings']:
                            finding_ids_seen.add(finding['Id'])
                            findings_detected.append(finding)
                            
                            self.logger.info(
                                f"New finding detected: {finding['Type']} "
                                f"(Severity: {finding['Severity']})"
                            )
                
                time_remaining = (monitoring_end_time - datetime.now(timezone.utc)).total_seconds()
                if poll_count % 2 == 0:
                    self.logger.info(f"Monitoring... {len(findings_detected)} findings detected, {time_remaining/60:.1f} min remaining")
            except Exception as e:
                self.logger.error(f"Error polling GuardDuty API: {e}")
            time.sleep(poll_interval_seconds)
        
        self.logger.info(f"Monitoring complete. Total findings: {len(findings_detected)}")
        return findings_detected
    
    def correlate_finding_with_attack(self, finding: Dict, 
                                     attack_start_time: datetime,
                                     tolerance_minutes: int = 5) -> Tuple[bool, Optional[float]]:
        try:
            finding_time_str = finding['Service']['EventFirstSeen']
            finding_time = datetime.fromisoformat(finding_time_str.replace('Z', '+00:00'))
            time_diff = (finding_time - attack_start_time).total_seconds()
            tolerance_seconds = tolerance_minutes * 60
            is_correlated = (time_diff >= 0) and (time_diff <= tolerance_seconds)
            
            if is_correlated:
                self.logger.info(
                    f"Finding correlated with attack. "
                    f"TTD: {time_diff:.2f} seconds ({time_diff/60:.2f} minutes)"
                )
                return True, time_diff
            else:
                self.logger.debug(f"Finding outside correlation window: {time_diff:.2f}s")
                return False, None
                
        except Exception as e:
            self.logger.error(f"Error correlating finding: {e}")
            return False, None
    
    def get_finding_summary(self, finding: Dict) -> Dict:
        return {
            'finding_id': finding['Id'],
            'finding_type': finding['Type'],
            'severity': finding['Severity'],
            'severity_label': self._severity_to_label(finding['Severity']),
            'title': finding.get('Title', 'N/A'),
            'description': finding.get('Description', 'N/A'),
            'first_seen': finding['Service']['EventFirstSeen'],
            'last_seen': finding['Service']['EventLastSeen'],
            'resource_type': finding['Resource']['ResourceType'],
            'account_id': finding['AccountId'],
            'region': finding['Region']
        }
    
    def _severity_to_label(self, severity: float) -> str:
        if severity >= 7.0:
            return 'High'
        elif severity >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def export_findings_to_json(self, findings: List[Dict], output_file: str):
        import json
        
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        
        self.logger.info(f"Exported {len(findings)} findings to {output_file}")
