import statistics
import json
from typing import Dict, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class MetricsCalculator:
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def calculate_detection_rate(self, test_results: List[Dict]) -> Dict:
        if not test_results:
            self.logger.warning("No test results provided")
            return {
                'detection_rate': 0.0,
                'true_positives': 0,
                'false_negatives': 0,
                'total_attacks': 0,
                'error': 'No test results'
            }
        
        true_positives = 0
        false_negatives = 0
        for r in test_results:
            if r.get('attack_executed', False) and r.get('finding_detected', False):
                true_positives += 1
            elif r.get('attack_executed', False) and not r.get('finding_detected', False):
                false_negatives += 1
        
        total_attacks = true_positives + false_negatives
        
        detection_rate = true_positives / total_attacks if total_attacks > 0 else 0.0
        
        self.logger.info(f"Detection Rate: {detection_rate:.2%}")
        self.logger.info(f"True Positives: {true_positives}/{total_attacks}")
        
        return {
            'detection_rate': detection_rate,
            'detection_rate_percent': detection_rate * 100,
            'true_positives': true_positives,
            'false_negatives': false_negatives,
            'total_attacks': total_attacks
        }
    
    def calculate_ttd_statistics(self, ttd_values: List[float]) -> Optional[Dict]:
        if not ttd_values:
            self.logger.warning("No TTD values provided")
            return None
        
        valid_ttd = []
        for t in ttd_values:
            if t is not None:
                valid_ttd.append(t)
        if len(valid_ttd) == 0:
            return None
        valid_ttd.sort()
        
        stats = {
            'count': len(valid_ttd),
            'mean_ttd_seconds': statistics.mean(valid_ttd),
            'median_ttd_seconds': statistics.median(valid_ttd),
            'min_ttd_seconds': min(valid_ttd),
            'max_ttd_seconds': max(valid_ttd),
        }
        
        if len(valid_ttd) > 1:
            stats['stdev_ttd_seconds'] = statistics.stdev(valid_ttd)
        else:
            stats['stdev_ttd_seconds'] = 0.0
        
        stats['mean_ttd_minutes'] = stats['mean_ttd_seconds'] / 60
        stats['median_ttd_minutes'] = stats['median_ttd_seconds'] / 60
        
        self.logger.info(f"TTD Statistics: Mean={stats['mean_ttd_seconds']:.2f}s, "
                        f"Median={stats['median_ttd_seconds']:.2f}s")
        
        return stats
    
    def calculate_false_positive_rate(self, baseline_findings: List[Dict],
                                     baseline_duration_hours: int) -> Dict:
        false_positives = len(baseline_findings)
        
        findings_hours = set()
        for finding in baseline_findings:
            try:
                from datetime import datetime
                finding_time = datetime.fromisoformat(
                    finding['Service']['EventFirstSeen'].replace('Z', '+00:00')
                )
                findings_hours.add(finding_time.hour)
            except:
                continue
        
        hours_with_findings = len(findings_hours)
        true_negatives = max(0, baseline_duration_hours - hours_with_findings)
        
        denominator = false_positives + true_negatives
        fpr = false_positives / denominator if denominator > 0 else 0.0
        
        self.logger.info(f"False Positive Rate: {fpr:.2%}")
        self.logger.info(f"False Positives: {false_positives} in {baseline_duration_hours} hours")
        
        return {
            'false_positive_rate': fpr,
            'false_positive_rate_percent': fpr * 100,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'baseline_duration_hours': baseline_duration_hours,
            'findings_per_hour': false_positives / baseline_duration_hours if baseline_duration_hours > 0 else 0
        }
    
    def calculate_metrics_by_attack_type(self, test_results: List[Dict]) -> Dict:
        attack_types = set(r.get('attack_type', 'Unknown') for r in test_results)
        
        metrics_by_type = {}
        
        for attack_type in attack_types:
            type_results = [
                r for r in test_results 
                if r.get('attack_type') == attack_type
            ]
            
            metrics_by_type[attack_type] = self.calculate_detection_rate(type_results)
            
            ttd_values = [
                r.get('time_to_detect') for r in type_results 
                if r.get('finding_detected') and r.get('time_to_detect') is not None
            ]
            
            if ttd_values:
                metrics_by_type[attack_type]['ttd_stats'] = self.calculate_ttd_statistics(ttd_values)
        
        return metrics_by_type
    
    def generate_summary_report(self, test_results: List[Dict],
                               baseline_findings: List[Dict],
                               baseline_duration_hours: int) -> Dict:
        self.logger.info("Generating summary report...")
        
        overall_metrics = self.calculate_detection_rate(test_results)
        
        ttd_values = [
            r.get('time_to_detect') for r in test_results 
            if r.get('finding_detected') and r.get('time_to_detect') is not None
        ]
        ttd_stats = self.calculate_ttd_statistics(ttd_values) if ttd_values else None
        
        fpr_metrics = self.calculate_false_positive_rate(
            baseline_findings, 
            baseline_duration_hours
        )
        
        by_type = self.calculate_metrics_by_attack_type(test_results)
        
        summary = {
            'overall_metrics': overall_metrics,
            'ttd_statistics': ttd_stats,
            'false_positive_metrics': fpr_metrics,
            'metrics_by_attack_type': by_type,
            'total_tests': len(test_results),
            'timestamp': str(datetime.now())
        }
        
        return summary
    
    def export_results(self, results: Dict, output_path: str):
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Results exported to {output_path}")
    
    def export_to_csv(self, test_results: List[Dict], output_path: str):
        import csv
        
        if not test_results:
            self.logger.warning("No results to export")
            return
        
        fieldnames = list(test_results[0].keys())
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(test_results)
        
        self.logger.info(f"Results exported to CSV: {output_path}")

from datetime import datetime
