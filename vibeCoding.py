"""
Python Security Monitoring System
Система за мониторинг и детектиране на съмнителни Python-базирани приложения
в корпоративна среда

Архитектурни компоненти:
1. Process Monitor - наблюдава Python процеси в реално време
2. Behavioral Analyzer - анализира поведение и детектира аномалии
3. Network Monitor - следи мрежови връзки от Python процеси
4. File System Watcher - мониторинг на файлове и persistence механизми
5. Alert Manager - управление на alerts и SIEM integration
6. Policy Engine - прилагане на корпоративни политики
"""

import os
import sys
import psutil
import hashlib
import json
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional
import re
import warnings
warnings.filterwarnings("ignore")


class ProcessMonitor:
    """Мониторинг на Python процеси в системата"""

    def __init__(self):
        self.suspicious_args = [
            'base64', 'exec', 'eval', 'compile',
            '__import__', 'socket.socket', 'subprocess',
            'os.system', 'CreateRemoteThread', 'VirtualAllocEx'
        ]
        self.whitelisted_paths = {
            r'C:\Program Files\Python*',
            r'C:\ProgramData\Anaconda*',
            r'C:\Users\*\AppData\Local\Programs\Python\*'
        }
        self.process_baseline = {}

    def scan_processes(self) -> List[Dict]:
        """Сканира всички активни Python процеси"""
        python_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'username', 'create_time']):
            try:
                if proc.info['name'] and 'python' in proc.info['name'].lower():
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'cmdline': proc.info['cmdline'],
                        'user': proc.info['username'],
                        'started': datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                        'suspicious': False,
                        'risk_score': 0,
                        'indicators': []
                    }

                    # Анализ на процеса
                    self._analyze_process(process_info, proc)
                    python_processes.append(process_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return python_processes

    def _analyze_process(self, info: Dict, proc: psutil.Process):
        """Анализира процес за съмнително поведение"""
        risk_score = 0

        # Проверка на command line arguments
        cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
        for suspicious_arg in self.suspicious_args:
            if suspicious_arg in cmdline:
                info['indicators'].append(f"Suspicious argument: {suspicious_arg}")
                risk_score += 10

        # Проверка на местоположение
        if info['exe']:
            exe_path = Path(info['exe'])
            is_whitelisted = any(
                exe_path.match(pattern.replace('*', '**'))
                for pattern in self.whitelisted_paths
            )

            if not is_whitelisted:
                info['indicators'].append(f"Non-standard location: {info['exe']}")
                risk_score += 15

            # Проверка за writable directories
            if self._is_user_writable(exe_path.parent):
                info['indicators'].append("Running from user-writable directory")
                risk_score += 20

        # Проверка на network connections
        try:
            connections = proc.connections()
            external_connections = [
                conn for conn in connections
                if conn.status == 'ESTABLISHED' and conn.raddr
            ]

            if len(external_connections) > 0:
                info['indicators'].append(f"Active network connections: {len(external_connections)}")
                risk_score += 5 * len(external_connections)

                # Проверка за known suspicious domains/IPs
                for conn in external_connections:
                    if self._is_suspicious_connection(conn):
                        info['indicators'].append(f"Suspicious connection: {conn.raddr}")
                        risk_score += 25

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Проверка на process memory
        try:
            memory_info = proc.memory_info()
            if memory_info.rss > 500 * 1024 * 1024:  # > 500MB
                info['indicators'].append(f"High memory usage: {memory_info.rss / 1024 / 1024:.2f}MB")
                risk_score += 10
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        info['risk_score'] = risk_score
        info['suspicious'] = risk_score >= 30

    def _is_user_writable(self, path: Path) -> bool:
        """Проверява дали директорията е writable от обикновен потребител"""
        user_writable_patterns = [
            r'.*\\AppData\\Local\\Temp.*',
            r'.*\\Downloads.*',
            r'.*\\Desktop.*',
            r'.*\\Documents.*'
        ]

        path_str = str(path)
        return any(re.match(pattern, path_str, re.IGNORECASE) for pattern in user_writable_patterns)

    def _is_suspicious_connection(self, conn) -> bool:
        """Проверява дали network connection е съмнителна"""
        # Suspicious ports
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999}
        if conn.raddr.port in suspicious_ports:
            return True

        # Discord API (често използван за C2)
        try:
            hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
            if 'discord' in hostname.lower():
                return True
        except:
            pass

        return False


class BehavioralAnalyzer:
    """Анализ на поведенчески модели"""

    def __init__(self):
        self.api_call_baseline = defaultdict(int)
        self.anomaly_threshold = 3  # Standard deviations

    def analyze_behavior(self, process_info: Dict) -> Dict:
        """Анализира поведението на процес"""
        behavior_analysis = {
            'privilege_escalation': False,
            'data_exfiltration_risk': False,
            'persistence_attempt': False,
            'code_injection_risk': False,
            'anomaly_score': 0
        }

        cmdline = ' '.join(process_info.get('cmdline', []))

        # Privilege escalation индикатори
        privilege_keywords = ['runas', 'elevate', 'admin', 'UAC']
        if any(kw in cmdline.lower() for kw in privilege_keywords):
            behavior_analysis['privilege_escalation'] = True
            behavior_analysis['anomaly_score'] += 25

        # Data exfiltration индикатори
        exfil_keywords = ['requests', 'urllib', 'ftplib', 'smtplib', 'paramiko']
        if any(kw in cmdline.lower() for kw in exfil_keywords):
            behavior_analysis['data_exfiltration_risk'] = True
            behavior_analysis['anomaly_score'] += 15

        # Persistence индикатори
        persistence_keywords = ['schtasks', 'registry', 'startup', 'run key']
        if any(kw in cmdline.lower() for kw in persistence_keywords):
            behavior_analysis['persistence_attempt'] = True
            behavior_analysis['anomaly_score'] += 30

        # Code injection индикатори
        injection_keywords = ['ctypes', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']
        if any(kw in cmdline.lower() for kw in injection_keywords):
            behavior_analysis['code_injection_risk'] = True
            behavior_analysis['anomaly_score'] += 35

        return behavior_analysis


class FileSystemWatcher:
    """Мониторинг на файловата система за persistence и suspicious files"""

    def __init__(self):
        self.monitored_locations = [
            r'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        ]
        self.registry_keys = [
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
        ]

    def scan_persistence_locations(self) -> List[Dict]:
        """Сканира известни persistence locations"""
        findings = []

        # Scan startup folders
        for location_pattern in self.monitored_locations:
            try:
                # Resolve wildcard patterns
                base_path = location_pattern.split('*')[0] if '*' in location_pattern else location_pattern
                if os.path.exists(base_path):
                    for root, dirs, files in os.walk(base_path):
                        for file in files:
                            if file.endswith('.py') or file.endswith('.pyw'):
                                file_path = os.path.join(root, file)
                                findings.append({
                                    'location': file_path,
                                    'type': 'startup_folder',
                                    'file': file,
                                    'hash': self._calculate_hash(file_path),
                                    'timestamp': datetime.now().isoformat()
                                })
            except Exception as e:
                print(f"Error scanning {location_pattern}: {e}")

        return findings

    def _calculate_hash(self, file_path: str) -> str:
        """Изчислява SHA256 hash на файл"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "N/A"


class AlertManager:
    """Управление на alerts и SIEM integration"""

    def __init__(self):
        self.alerts = []
        self.alert_threshold = {
            'low': 20,
            'medium': 40,
            'high': 60,
            'critical': 80
        }

    def create_alert(self, severity: str, category: str, details: Dict):
        """Създава security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'details': details,
            'status': 'new'
        }

        self.alerts.append(alert)
        self._log_to_siem(alert)

        return alert

    def _log_to_siem(self, alert: Dict):
        """Логване към SIEM система (mock implementation)"""
        # В реална система - integration с Splunk, QRadar, Sentinel, etc.
        siem_log = {
            'event_type': 'python_security_alert',
            'event_data': alert,
            'source': 'python_security_monitor',
            'host': socket.gethostname()
        }

        # Mock: Print to console (в продукция - API call към SIEM)
        print(f"\n[SIEM LOG] {json.dumps(siem_log, indent=2)}")

    def get_alerts_summary(self) -> Dict:
        """Връща резюме на alerts"""
        summary = {
            'total': len(self.alerts),
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'recent_critical': []
        }

        for alert in self.alerts:
            summary['by_severity'][alert['severity']] += 1
            summary['by_category'][alert['category']] += 1

            if alert['severity'] == 'critical':
                summary['recent_critical'].append(alert)

        return dict(summary)


class PolicyEngine:
    """Policy enforcement engine"""

    def __init__(self):
        self.policies = {
            'allow_user_writable_execution': False,
            'require_digital_signature': True,
            'block_known_malicious_patterns': True,
            'max_risk_score': 50,
            'quarantine_on_critical': True
        }

    def evaluate_compliance(self, process_info: Dict, behavior: Dict) -> Dict:
        """Оценява съответствието с политиките"""
        violations = []
        actions = []

        # Policy 1: No execution from user-writable directories
        if not self.policies['allow_user_writable_execution']:
            if any('user-writable' in ind for ind in process_info.get('indicators', [])):
                violations.append('Execution from user-writable directory')
                actions.append('TERMINATE_PROCESS')

        # Policy 2: Risk score threshold
        if process_info.get('risk_score', 0) > self.policies['max_risk_score']:
            violations.append(
                f"Risk score {process_info['risk_score']} exceeds threshold {self.policies['max_risk_score']}")
            actions.append('QUARANTINE')

        # Policy 3: Critical behavior detection
        if behavior.get('code_injection_risk') or behavior.get('persistence_attempt'):
            violations.append('Critical behavior detected')
            if self.policies['quarantine_on_critical']:
                actions.append('IMMEDIATE_QUARANTINE')

        return {
            'compliant': len(violations) == 0,
            'violations': violations,
            'recommended_actions': actions
        }


class SecurityMonitoringSystem:
    """Главен клас на системата за мониторинг"""

    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.fs_watcher = FileSystemWatcher()
        self.alert_manager = AlertManager()
        self.policy_engine = PolicyEngine()
        self.running = False

    def start_monitoring(self, interval: int = 60):
        """Стартира continuous monitoring"""
        self.running = True
        print(f"[*] Python Security Monitoring System Started")
        print(f"[*] Scan interval: {interval} seconds")
        print(f"[*] Hostname: {socket.gethostname()}")
        print(f"[*] Timestamp: {datetime.now().isoformat()}\n")

        while self.running:
            try:
                self._perform_scan()
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\n[*] Stopping monitoring...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Error during monitoring: {e}")
                time.sleep(interval)

    def _perform_scan(self):
        """Извършва пълен scan"""
        print(f"\n{'=' * 80}")
        print(f"[SCAN] Starting security scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 80}\n")

        # 1. Process scanning
        python_processes = self.process_monitor.scan_processes()
        print(f"[+] Found {len(python_processes)} Python processes")

        # 2. Analyze each process
        for proc in python_processes:
            if proc['suspicious']:
                print(f"\n[!] SUSPICIOUS PROCESS DETECTED:")
                print(f"    PID: {proc['pid']}")
                print(f"    Name: {proc['name']}")
                print(f"    User: {proc['user']}")
                print(f"    Risk Score: {proc['risk_score']}")
                print(f"    Indicators:")
                for ind in proc['indicators']:
                    print(f"      - {ind}")

                # Behavioral analysis
                behavior = self.behavioral_analyzer.analyze_behavior(proc)
                print(f"    Behavioral Analysis:")
                for key, value in behavior.items():
                    if value and key != 'anomaly_score':
                        print(f"      - {key}: {value}")
                print(f"    Anomaly Score: {behavior['anomaly_score']}")

                # Policy evaluation
                compliance = self.policy_engine.evaluate_compliance(proc, behavior)
                if not compliance['compliant']:
                    print(f"    Policy Violations:")
                    for violation in compliance['violations']:
                        print(f"      - {violation}")
                    print(f"    Recommended Actions: {', '.join(compliance['recommended_actions'])}")

                # Create alert
                severity = self._calculate_severity(proc['risk_score'], behavior['anomaly_score'])
                self.alert_manager.create_alert(
                    severity=severity,
                    category='suspicious_python_process',
                    details={
                        'process': proc,
                        'behavior': behavior,
                        'compliance': compliance
                    }
                )

        # 3. File system scan
        persistence_findings = self.fs_watcher.scan_persistence_locations()
        if persistence_findings:
            print(f"\n[!] Found {len(persistence_findings)} Python files in persistence locations:")
            for finding in persistence_findings:
                print(f"    - {finding['location']}")
                print(f"      Hash: {finding['hash']}")

                self.alert_manager.create_alert(
                    severity='medium',
                    category='persistence_detection',
                    details=finding
                )

        # 4. Summary
        summary = self.alert_manager.get_alerts_summary()
        print(f"\n{'=' * 80}")
        print(f"[SUMMARY] Scan completed")
        print(f"{'=' * 80}")
        print(f"Total Alerts: {summary['total']}")
        print(f"By Severity: {dict(summary['by_severity'])}")
        print(f"Critical Alerts: {len(summary['recent_critical'])}")
        print(f"{'=' * 80}\n")

    def _calculate_severity(self, risk_score: int, anomaly_score: int) -> str:
        """Изчислява severity level"""
        total_score = risk_score + anomaly_score

        if total_score >= 80:
            return 'critical'
        elif total_score >= 60:
            return 'high'
        elif total_score >= 40:
            return 'medium'
        else:
            return 'low'

    def generate_report(self) -> str:
        """Генерира security report"""
        report = []
        report.append("=" * 80)
        report.append("PYTHON SECURITY MONITORING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Hostname: {socket.gethostname()}")
        report.append("")

        summary = self.alert_manager.get_alerts_summary()
        report.append("ALERT SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Alerts: {summary['total']}")
        report.append(f"By Severity:")
        for severity, count in summary['by_severity'].items():
            report.append(f"  - {severity.upper()}: {count}")
        report.append("")

        if summary['recent_critical']:
            report.append("CRITICAL ALERTS")
            report.append("-" * 40)
            for alert in summary['recent_critical']:
                report.append(f"Time: {alert['timestamp']}")
                report.append(f"Category: {alert['category']}")
                report.append(f"Details: {json.dumps(alert['details'], indent=2)}")
                report.append("")

        report.append("=" * 80)

        return "\n".join(report)


def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  Python Security Monitoring System                            ║
    ║  Корпоративна киберсигурност - Мониторинг на Python процеси   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    system = SecurityMonitoringSystem()

    print("\nOptions:")
    print("1. Perform single scan")
    print("2. Start continuous monitoring (60 sec interval)")
    print("3. Generate report")

    try:
        choice = input("\nSelect option (1-3): ").strip()

        if choice == '1':
            system._perform_scan()
        elif choice == '2':
            system.start_monitoring(interval=60)
        elif choice == '3':
            report = system.generate_report()
            print(report)

            # Save to file
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(report)
            print(f"\n[+] Report saved to: {filename}")
        else:
            print("[!] Invalid option")

    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()