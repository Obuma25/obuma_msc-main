#!/usr/bin/env python3

import boto3
import time
import os
import statistics
import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
from guardduty_monitor import GuardDutyMonitor


class DNSExfiltrationTestSuite:
    def __init__(self, ec2_instance_id: str, aws_region: str = 'eu-west-2'):
        self.ec2_instance_id = ec2_instance_id
        self.aws_region = aws_region
        self.monitor = GuardDutyMonitor(aws_region)
        self.ssm_client = boto3.client(
            'ssm',
            region_name=aws_region,
            config=Config(
                connect_timeout=10,
                read_timeout=60,
                retries={'max_attempts': 10, 'mode': 'standard'},
            ),
        )
        self.results = []

    def _call_ssm(self, method_name: str, **kwargs):
        last_error = None
        for attempt in range(1, 6):
            try:
                return getattr(self.ssm_client, method_name)(**kwargs)
            except EndpointConnectionError as exc:
                last_error = exc
            except (BotoCoreError, ClientError) as exc:
                if "Could not connect to the endpoint URL" not in str(exc):
                    raise
                last_error = exc

            time.sleep(min(5 * attempt, 20))

        if last_error is not None:
            raise last_error
        raise RuntimeError(f"SSM call failed without a captured error: {method_name}")
        
    def execute_dns_exfiltration(self, test_id: str, domain: str, 
                                 data_size_kb: int, queries_per_second: int) -> Dict[str, Any]:
        attack_time = datetime.now(timezone.utc)
        min_domains = 900
        bytes_per_domain = 63
        data_bytes = data_size_kb * 1024
        estimated_queries = max(min_domains, int((data_bytes * 1.6) / bytes_per_domain) + 1)
        if queries_per_second > 0:
            sleep_time_ms = int(1000 / queries_per_second)
        else:
            sleep_time_ms = 0

        bash_script = f"""#!/bin/bash

QUERY_COUNT={estimated_queries}
SLEEP_MS={sleep_time_ms}

SUCCESSFUL=0

for i in $(seq 1 $QUERY_COUNT); do
    RANDOM_DOMAIN=$(openssl rand -hex 16)
    
    TLD_INDEX=$((RANDOM % 6))
    case $TLD_INDEX in
        0) TLD="com" ;;
        1) TLD="net" ;;
        2) TLD="org" ;;
        3) TLD="info" ;;
        4) TLD="biz" ;;
        5) TLD="xyz" ;;
    esac
    
    DOMAIN_NAME="$RANDOM_DOMAIN.$TLD"
    
    dig +short +timeout=2 +tries=1 @10.0.0.2 "$DOMAIN_NAME" > /dev/null 2>&1
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 9 ] || [ $EXIT_CODE -eq 10 ]; then
        SUCCESSFUL=$((SUCCESSFUL + 1))
    fi
    
    if [ $SLEEP_MS -gt 0 ]; then
        sleep 0.$(printf "%03d" $SLEEP_MS)
    fi
done
"""
        
        try:
            try:
                instance_info = self._call_ssm(
                    'describe_instance_information',
                    Filters=[{'Key': 'InstanceIds', 'Values': [self.ec2_instance_id]}]
                )
                if instance_info['InstanceInformationList']:
                    ping_status = instance_info['InstanceInformationList'][0].get('PingStatus', 'Unknown')
                    if ping_status != 'Online':
                        pass
            except Exception as e:
                pass
            
            
            response = self._call_ssm(
                'send_command',
                InstanceIds=[self.ec2_instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': [bash_script]},
                Comment=f'GuardDuty Test - DNS Exfiltration {test_id}',
                TimeoutSeconds=600
            )
            
            command_id = response['Command']['CommandId']
            
            max_wait = 900
            wait_interval = 10
            elapsed = 0
            pending_stuck_count = 0
            while elapsed < max_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
                
                try:
                    invocation = self._call_ssm(
                        'get_command_invocation',
                        CommandId=command_id,
                        InstanceId=self.ec2_instance_id
                    )
                    
                    status = invocation['Status']
                    status_details = invocation.get('StatusDetails', '')
                    
                    if status == 'Pending':
                        pending_stuck_count += 1
                        if pending_stuck_count >= 3:
                            if 'Delayed' in status_details or elapsed > 60:
                                pass
                                return {
                                    'success': False,
                                    'error': f'SSM agent disconnected - command stuck in Pending. StatusDetails: {status_details}',
                                    'queries_sent': 0,
                                    'attack_time': attack_time.isoformat(),
                                    'command_id': command_id
                                }
                    
                    if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                        output = invocation.get('StandardOutputContent', '')
                        error = invocation.get('StandardErrorContent', '')
                        
                        if status == 'Success':
                            result_dict = {
                                'success': True,
                                'queries_sent': estimated_queries,
                                'successful_queries': estimated_queries,
                                'data_size_kb': data_size_kb,
                                'total_time_seconds': elapsed,
                                'attack_time': attack_time.isoformat(),
                                'command_id': command_id,
                                'unique_domains': estimated_queries
                            }
                            return result_dict
                        else:
                            return {
                                'success': False,
                                'error': f"SSM command {status}: {error[:200]}",
                                'queries_sent': 0,
                                'attack_time': attack_time.isoformat()
                            }
                    
                    if status != 'Pending':
                        pending_stuck_count = 0
                    
                except self.ssm_client.exceptions.InvocationDoesNotExist:
                    continue
            
            return {
                'success': False,
                'error': 'Timeout waiting for SSM command completion',
                'queries_sent': 0,
                'attack_time': attack_time.isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'queries_sent': 0,
                'attack_time': attack_time.isoformat()
            }
    
    def run_test(self, test_config: Dict[str, Any], 
                 monitoring_duration_minutes: int = 10) -> Dict[str, Any]:
        test_id = test_config['test_id']
        
        start_time = datetime.now(timezone.utc)
        attack_result = self.execute_dns_exfiltration(
            test_id=test_id,
            domain=test_config['domain'],
            data_size_kb=test_config['data_size_kb'],
            queries_per_second=test_config['queries_per_second']
        )
        attack_end_time = datetime.now(timezone.utc)

        monitoring_start_time = attack_end_time if attack_end_time > start_time else start_time
        findings = self.monitor.monitor_findings(
            attack_start_time=monitoring_start_time,
            duration_minutes=monitoring_duration_minutes,
            poll_interval_seconds=60,
        )
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
                    'description': finding.get('Description', ''),
                    'title': finding.get('Title', '')
                })
        
        result = {
            'test_id': test_id,
            'description': test_config['description'],
            'data_size_kb': test_config['data_size_kb'],
            'queries_per_second': test_config['queries_per_second'],
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
    
    def run_full_suite(self, monitoring_duration_minutes: int = 45) -> List[Dict[str, Any]]:
        TEST_DOMAIN = "unused"

        test_cases = [
            # --- Original 5 scenarios (EX-01 to EX-05) ---
            {
                'test_id': 'EX-01',
                'description': 'DNS Tunnelling - Small volume, moderate rate',
                'domain': TEST_DOMAIN,
                'data_size_kb': 50,
                'queries_per_second': 10
            },
            {
                'test_id': 'EX-02',
                'description': 'DNS Tunnelling - Medium volume, moderate rate',
                'domain': TEST_DOMAIN,
                'data_size_kb': 100,
                'queries_per_second': 10
            },
            {
                'test_id': 'EX-03',
                'description': 'DNS Tunnelling - Small volume, high rate',
                'domain': TEST_DOMAIN,
                'data_size_kb': 50,
                'queries_per_second': 20
            },
            {
                'test_id': 'EX-04',
                'description': 'DNS Tunnelling - Medium volume, slow rate',
                'domain': TEST_DOMAIN,
                'data_size_kb': 75,
                'queries_per_second': 5
            },
            {
                'test_id': 'EX-05',
                'description': 'DNS Tunnelling - Low-and-slow (threshold test)',
                'domain': TEST_DOMAIN,
                'data_size_kb': 25,
                'queries_per_second': 2
            },
            # --- Expanded scenarios (EX-06 to EX-10) ---
            {
                'test_id': 'EX-06',
                'description': 'DNS Tunnelling - High volume, high rate burst',
                'domain': TEST_DOMAIN,
                'data_size_kb': 200,
                'queries_per_second': 25
            },
            {
                'test_id': 'EX-07',
                'description': 'DNS Tunnelling - Large volume, moderate rate sustained',
                'domain': TEST_DOMAIN,
                'data_size_kb': 150,
                'queries_per_second': 10
            },
            {
                'test_id': 'EX-08',
                'description': 'DNS Tunnelling - Minimal volume, very slow drip',
                'domain': TEST_DOMAIN,
                'data_size_kb': 10,
                'queries_per_second': 1
            },
            {
                'test_id': 'EX-09',
                'description': 'DNS Tunnelling - Medium volume, high rate short burst',
                'domain': TEST_DOMAIN,
                'data_size_kb': 75,
                'queries_per_second': 15
            },
            {
                'test_id': 'EX-10',
                'description': 'DNS Tunnelling - Large volume, slow rate extended',
                'domain': TEST_DOMAIN,
                'data_size_kb': 125,
                'queries_per_second': 3
            }
        ]
        
        results = []
        
        for i, test_config in enumerate(test_cases, 1):
            result = self.run_test(test_config, monitoring_duration_minutes)
            results.append(result)
            self.results.append(result)
            
            if i < len(test_cases):
                time.sleep(30)
        
        self._print_summary(results)
        
        self._save_results(results)
        
        return results
    
    def _print_summary(self, results: List[Dict[str, Any]]):
        pass
    
    def _save_results(self, results: List[Dict[str, Any]]):
        detected_count = sum(1 for r in results if r['detected'])
        detection_rate = (detected_count / len(results) * 100) if results else 0
        
        ttd_values = []
        for r in results:
            if r['detected'] and r['findings']:
                for f in r['findings']:
                    ttd_values.append(f['time_to_detect_seconds'])
        
        ttd_stats = None
        if ttd_values:
            ttd_stats = {
                'mean_seconds': statistics.mean(ttd_values),
                'median_seconds': statistics.median(ttd_values),
                'min_seconds': min(ttd_values),
                'max_seconds': max(ttd_values),
                'stddev_seconds': statistics.stdev(ttd_values) if len(ttd_values) > 1 else 0
            }
        
        output = {
            'test_suite': 'DNS Exfiltration Detection Analysis',
            'hypothesis': 'H2: Observing GuardDuty detection behavior for DNS exfiltration under controlled test conditions',
            'aws_region': self.aws_region,
            'execution_date': datetime.now(timezone.utc).isoformat(),
            'total_tests': len(results),
            'detection_summary': {
                'total_tests': len(results),
                'successful_attacks': sum(1 for r in results if r['attack_executed']),
                'detected': detected_count,
                'detection_rate_percent': detection_rate,
                'observations': {
                    'detection_rate_observed': detection_rate,
                    'ttd_median_observed': ttd_stats['median_seconds'] if ttd_stats else None
                }
            },
            'ttd_statistics': ttd_stats,
            'test_results': results
        }
        
        filename = f"dns_exfil_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)


def main():
    import os
    import sys
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    AWS_REGION = os.getenv("AWS_REGION", "eu-west-2")
    EC2_INSTANCE_ID = os.getenv("EC2_INSTANCE_ID", "<EC2_INSTANCE_ID>")
    MONITORING_DURATION = 15

    print(f"\n{'='*60}")
    print(f"DNS EXFILTRATION TEST SUITE - 10 Scenarios")
    print(f"EC2 Instance: {EC2_INSTANCE_ID}")
    print(f"Region: {AWS_REGION}")
    print(f"Monitoring: {MONITORING_DURATION} min per test")
    print(f"{'='*60}\n")

    suite = DNSExfiltrationTestSuite(
        ec2_instance_id=EC2_INSTANCE_ID,
        aws_region=AWS_REGION
    )
    results = suite.run_full_suite(monitoring_duration_minutes=MONITORING_DURATION)

    detected_count = sum(1 for r in results if r['detected'])
    detection_rate = (detected_count / len(results) * 100) if results else 0

    print(f"\n{'='*60}")
    print(f"COMPLETE - {len(results)} tests executed")
    print(f"Detection rate: {detected_count}/{len(results)} ({detection_rate:.0f}%)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
