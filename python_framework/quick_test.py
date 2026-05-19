#!/usr/bin/env python3

from main import GuardDutyTestRunner
from datetime import datetime
import json
import os

target_url = os.getenv('TARGET_URL', 'http://<JUICE_SHOP_IP>')
aws_region = os.getenv('AWS_REGION', 'eu-west-2')

runner = GuardDutyTestRunner(target_url, aws_region)

result = runner.run_sqli_test(
    test_id='TEST-01',
    endpoint='/rest/user/login',
    parameter='email',
    payload="' OR '1'='1--",
    technique='B'
)

from guardduty_monitor import GuardDutyMonitor
original = runner.monitor.monitor_findings
runner.monitor.monitor_findings = lambda start, duration_minutes=2, poll_interval_seconds=30: original(start, 2, 30)

with open('test_result.json', 'w') as f:
    json.dump(result, f, indent=2, default=str)
