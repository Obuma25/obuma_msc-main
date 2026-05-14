#!/usr/bin/env python3

import argparse
import logging
import sys
from typing import Any, Dict, List, Optional

from dns_exfil_test_suite import DNSExfiltrationTestSuite
from sqli_test_suite import SQLiTestSuite


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger(__name__)


class GuardDutyTestRunner:
    def __init__(
        self,
        target_url: Optional[str] = None,
        aws_region: str = "eu-west-2",
        ec2_instance_id: Optional[str] = None,
    ):
        self.target_url = target_url
        self.aws_region = aws_region
        self.ec2_instance_id = ec2_instance_id
        logger.info("GuardDuty testing framework initialised")
        logger.info("AWS region: %s", aws_region)

    def run_sqli_test(
        self,
        test_id: str,
        endpoint: str,
        parameter: str,
        payload: str,
        technique: str,
        method: str = "POST",
        monitoring_duration_minutes: int = 5,
    ) -> Dict[str, Any]:
        if not self.target_url:
            raise ValueError("target_url is required for SQL injection tests")

        suite = SQLiTestSuite(self.target_url, self.aws_region)
        return suite.run_test(
            {
                "test_id": test_id,
                "description": f"{technique} SQL injection test",
                "technique": technique,
                "endpoint": endpoint,
                "payload": payload,
                "param_name": parameter,
                "method": method,
            },
            monitoring_duration_minutes=monitoring_duration_minutes,
        )

    def run_dns_exfil_test(
        self,
        test_id: str,
        domain: str,
        data_size_kb: int,
        throttle_qps: int,
        monitoring_duration_minutes: int = 15,
    ) -> Dict[str, Any]:
        if not self.ec2_instance_id:
            raise ValueError("ec2_instance_id is required for DNS exfiltration tests")

        suite = DNSExfiltrationTestSuite(self.ec2_instance_id, self.aws_region)
        return suite.run_test(
            {
                "test_id": test_id,
                "description": "DNS tunnelling test",
                "domain": domain,
                "data_size_kb": data_size_kb,
                "queries_per_second": throttle_qps,
            },
            monitoring_duration_minutes=monitoring_duration_minutes,
        )

    def run_all_tests(self, suite_name: str = "all") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        if suite_name in ("all", "sqli"):
            if not self.target_url:
                raise ValueError("--target-url is required when running SQL injection tests")
            sqli_suite = SQLiTestSuite(self.target_url, self.aws_region)
            results.extend(sqli_suite.run_full_suite(monitoring_duration_minutes=5))

        if suite_name in ("all", "dns"):
            if not self.ec2_instance_id:
                raise ValueError("--instance-id is required when running DNS exfiltration tests")
            dns_suite = DNSExfiltrationTestSuite(self.ec2_instance_id, self.aws_region)
            results.extend(dns_suite.run_full_suite(monitoring_duration_minutes=15))

        return results


def main():
    parser = argparse.ArgumentParser(description="GuardDuty empirical testing framework")
    parser.add_argument("--suite", choices=["all", "sqli", "dns"], default="all")
    parser.add_argument("--target-url", help="Target application URL for SQL injection tests")
    parser.add_argument("--instance-id", help="EC2 instance ID for DNS exfiltration tests")
    parser.add_argument("--region", default="eu-west-2", help="AWS region")

    args = parser.parse_args()
    runner = GuardDutyTestRunner(args.target_url, args.region, args.instance_id)
    results = runner.run_all_tests(args.suite)

    logger.info("Total tests executed: %s", len(results))


if __name__ == "__main__":
    main()
