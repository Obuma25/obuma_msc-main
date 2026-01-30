from guardduty_monitor import GuardDutyMonitor
from datetime import datetime, timezone
import time
import json

def main():
    monitor = GuardDutyMonitor('eu-west-2')
    start_time = datetime.now(timezone.utc)
    
    try:
        time.sleep(24 * 60 * 60)
    except KeyboardInterrupt:
        pass
    
    end_time = datetime.now(timezone.utc)
    duration_minutes = int((end_time - start_time).total_seconds() / 60)
    
    findings = monitor.monitor_findings(start_time, duration_minutes=duration_minutes)
    
    output_file = 'baseline_findings.json'
    monitor.export_findings_to_json(findings, output_file)
    
    return findings

if __name__ == '__main__':
    main()

