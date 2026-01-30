import logging
import json
from datetime import datetime
from pathlib import Path
import sys

from attack_orchestrator import AttackOrchestrator
from guardduty_monitor import GuardDutyMonitor
from metrics_calculator import MetricsCalculator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_execution.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


class GuardDutyTestRunner:
    def __init__(self, target_url: str, aws_region: str = 'eu-west-2'):
        self.target_url = target_url
        self.aws_region = aws_region
        self.attacker = AttackOrchestrator(target_url)
        self.monitor = GuardDutyMonitor(aws_region)
        self.calculator = MetricsCalculator()
        self.results_dir = Path('results')
        self.results_dir.mkdir(exist_ok=True)
        logger.info("GuardDuty Testing Framework Initialized")
        logger.info(f"Target URL: {target_url}")
        logger.info(f"AWS Region: {aws_region}")
    
    def run_sqli_test(self, test_id: str, endpoint: str, parameter: str,
                     payload: str, technique: str) -> dict:
        logger.info(f"Executing SQL injection test: {test_id}")
        logger.info(f"Endpoint: {endpoint}, Technique: {technique}")
        
        attack_result = self.attacker.execute_sqli_attack(
            endpoint, parameter, payload, technique
        )
        
        if not attack_result.get('success'):
            logger.warning(f"Attack {test_id} failed to execute successfully")
        
        attack_start = datetime.fromisoformat(attack_result['start_time'])
        findings = self.monitor.monitor_findings(
            attack_start,
            duration_minutes=30,
            poll_interval_seconds=60
        )
        
        correlated_findings = []
        time_to_detect = None
        
        for finding in findings:
            is_correlated, ttd = self.monitor.correlate_finding_with_attack(
                finding, attack_start, tolerance_minutes=5
            )
            if is_correlated:
                correlated_findings.append(finding)
                if time_to_detect is None or ttd < time_to_detect:
                    time_to_detect = ttd
        
        result = {
            'test_id': test_id,
            'attack_type': 'SQL_Injection',
            'technique': technique,
            'endpoint': endpoint,
            'attack_executed': attack_result.get('success', False),
            'finding_detected': len(correlated_findings) > 0,
            'time_to_detect': time_to_detect,
            'findings_count': len(correlated_findings),
            'attack_result': attack_result,
            'findings': [self.monitor.get_finding_summary(f) for f in correlated_findings]
        }
        
        detected_status = 'YES' if result['finding_detected'] else 'NO'
        logger.info(f"Test {test_id} Complete: Detection={detected_status}")
        return result
    
    def run_dns_exfil_test(self, test_id: str, domain: str, 
                          data_size_kb: int, throttle_qps: int) -> dict:
        logger.info(f"Executing DNS exfiltration test: {test_id}")
        logger.info(f"Domain: {domain}, Data size: {data_size_kb}KB, Query rate: {throttle_qps} QPS")
        
        attack_result = self.attacker.execute_dns_exfiltration(
            domain, data_size_kb, throttle_qps
        )
        
        attack_start = datetime.fromisoformat(attack_result['start_time'])
        findings = self.monitor.monitor_findings(attack_start, duration_minutes=30)
        
        correlated_findings = []
        time_to_detect = None
        for finding in findings:
            is_correlated, ttd = self.monitor.correlate_finding_with_attack(finding, attack_start)
            if is_correlated:
                correlated_findings.append(finding)
                if time_to_detect is None or (ttd is not None and ttd < time_to_detect):
                    time_to_detect = ttd
        
        result = {
            'test_id': test_id,
            'attack_type': 'DNS_Exfiltration',
            'domain': domain,
            'data_size_kb': data_size_kb,
            'throttle_qps': throttle_qps,
            'attack_executed': attack_result.get('success', False),
            'finding_detected': len(correlated_findings) > 0,
            'time_to_detect': time_to_detect,
            'findings_count': len(correlated_findings),
            'attack_result': attack_result,
            'findings': [self.monitor.get_finding_summary(f) for f in correlated_findings]
        }
        
        logger.info(f"Test {test_id} completed. Detection: {result['finding_detected']}")
        
        return result
    
    def run_all_tests(self):
        logger.info("Starting test suite execution")
        
        all_results = []
        
        sqli_tests = [
            ('SQL-01', '/rest/user/login', 'email', "' OR '1'='1--", 'B'),
            ('SQL-02', '/api/Products', 'q', "' UNION SELECT", 'U'),
            ('SQL-03', '/rest/products/search', 'q', "' AND '1'='1", 'B'),
            ('SQL-04', '/api/Feedbacks', 'id', "'; SLEEP(5)--", 'T'),
            ('SQL-05', '/rest/basket/1', 'id', "' AND 1=CONVERT(int,@@version)--", 'E'),
            ('SQL-06', '/rest/user/registration', 'email', "' OR 1=1--", 'B'),
            ('SQL-07', '/api/Products', 'id', "' UNION SELECT NULL,NULL--", 'U'),
            ('SQL-08', '/rest/user/login', 'email', "admin'--", 'B'),
            ('SQL-09', '/api/Feedbacks', 'comment', "'; WAITFOR DELAY '00:00:05'--", 'T'),
            ('SQL-10', '/rest/products/search', 'q', "' OR 'x'='x", 'B'),
        ]
        
        for test_id, endpoint, param, payload, technique in sqli_tests:
            result = self.run_sqli_test(test_id, endpoint, param, payload, technique)
            all_results.append(result)
            self._save_results(all_results, 'intermediate_results.json')
        
        dns_exfil_domain = 'exfil.example.com'
        dns_tests = [
            ('EX-01', dns_exfil_domain, 100, 10),
            ('EX-02', dns_exfil_domain, 500, 10),
            ('EX-03', dns_exfil_domain, 100, 5),
            ('EX-04', dns_exfil_domain, 1000, 10),
            ('EX-05', dns_exfil_domain, 10, 2),
        ]
        
        for test_id, domain, size_kb, qps in dns_tests:
            result = self.run_dns_exfil_test(test_id, domain, size_kb, qps)
            all_results.append(result)
            
            self._save_results(all_results, 'intermediate_results.json')
        
        logger.info("Generating metrics summary")
        
        summary = self.calculator.generate_summary_report(
            all_results,
            baseline_findings=[],
            baseline_duration_hours=24
        )
        
        self._save_results(all_results, 'final_test_results.json')
        self._save_results(summary, 'metrics_summary.json')
        self.calculator.export_to_csv(all_results, self.results_dir / 'results.csv')
        
        logger.info("Test suite execution completed")
        logger.info(f"Results directory: {self.results_dir}")
        
        return all_results, summary
    
    def _save_results(self, results, filename: str):
        output_path = self.results_dir / filename
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='GuardDuty Testing Framework')
    parser.add_argument('--target-url', required=True, 
                       help='Target URL (e.g., http://1.2.3.4)')
    parser.add_argument('--region', default='eu-west-2',
                       help='AWS region (default: eu-west-2)')
    
    args = parser.parse_args()
    
    runner = GuardDutyTestRunner(args.target_url, args.region)
    _results, summary = runner.run_all_tests()
    
    logger.info(f"Total tests executed: {summary['total_tests']}")
    logger.info(f"Overall detection rate: {summary['overall_metrics']['detection_rate_percent']:.1f}%")
    if summary['ttd_statistics']:
        logger.info(f"Mean time to detect: {summary['ttd_statistics']['mean_ttd_seconds']:.2f} seconds")


if __name__ == '__main__':
    main()
