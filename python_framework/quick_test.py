#!/usr/bin/env python3

from main import GuardDutyTestRunner
from datetime import datetime
import json

runner = GuardDutyTestRunner('http://13.43.131.11', 'eu-west-2')

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

