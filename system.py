"""Главен оркестратор на системата за мониторинг"""

import json
import logging
import socket
import threading
from datetime import datetime
from typing import Dict

from alerts import AlertManager, PolicyEngine
from config import (
    DEFAULT_SCAN_INTERVAL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from monitors import BehavioralAnalyzer, FileSystemWatcher, ProcessMonitor

logger = logging.getLogger("security_monitor.system")


class SecurityMonitoringSystem:
    """Главен клас на системата за мониторинг"""

    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.fs_watcher = FileSystemWatcher()
        self.alert_manager = AlertManager()
        self.policy_engine = PolicyEngine()
        self._stop_event = threading.Event()

    def start_monitoring(self, interval: int = DEFAULT_SCAN_INTERVAL):
        """Стартира continuous monitoring"""
        self._stop_event.clear()
        logger.info("Python Security Monitoring System Started")
        logger.info("Scan interval: %d seconds", interval)
        logger.info("Hostname: %s", socket.gethostname())
        logger.info("Timestamp: %s", datetime.now().isoformat())

        while not self._stop_event.is_set():
            try:
                self.perform_scan()
                self._stop_event.wait(timeout=interval)
            except KeyboardInterrupt:
                logger.info("Stopping monitoring...")
                self.stop_monitoring()
                break
            except Exception as e:
                logger.error("Error during monitoring: %s", e)
                self._stop_event.wait(timeout=interval)

    def stop_monitoring(self):
        """Спира continuous monitoring"""
        self._stop_event.set()

    def perform_scan(self):
        """Извършва пълен scan"""
        separator = "=" * 80
        logger.info(separator)
        logger.info(
            "Starting security scan at %s",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        logger.info(separator)

        # 1. Process scanning
        python_processes = self.process_monitor.scan_processes()
        logger.info("Found %d Python processes", len(python_processes))

        # 2. Analyze each process
        for proc in python_processes:
            if proc["suspicious"]:
                logger.warning("SUSPICIOUS PROCESS DETECTED:")
                logger.warning("  PID: %s", proc["pid"])
                logger.warning("  Name: %s", proc["name"])
                logger.warning("  User: %s", proc["user"])
                logger.warning("  Risk Score: %s", proc["risk_score"])
                logger.warning("  Indicators:")
                for ind in proc["indicators"]:
                    logger.warning("    - %s", ind)

                behavior = self.behavioral_analyzer.analyze_behavior(proc)
                logger.warning("  Behavioral Analysis:")
                for key, value in behavior.items():
                    if value and key != "anomaly_score":
                        logger.warning("    - %s: %s", key, value)
                logger.warning("  Anomaly Score: %s", behavior["anomaly_score"])

                compliance = self.policy_engine.evaluate_compliance(proc, behavior)
                if not compliance["compliant"]:
                    logger.warning("  Policy Violations:")
                    for violation in compliance["violations"]:
                        logger.warning("    - %s", violation)
                    logger.warning(
                        "  Recommended Actions: %s",
                        ", ".join(compliance["recommended_actions"]),
                    )

                severity = self._calculate_severity(
                    proc["risk_score"], behavior["anomaly_score"]
                )
                self.alert_manager.create_alert(
                    severity=severity,
                    category="suspicious_python_process",
                    details={
                        "process": proc,
                        "behavior": behavior,
                        "compliance": compliance,
                    },
                )

        # 3. File system scan
        persistence_findings = self.fs_watcher.scan_persistence_locations()
        if persistence_findings:
            logger.warning(
                "Found %d Python files in persistence locations:",
                len(persistence_findings),
            )
            for finding in persistence_findings:
                logger.warning("  - %s", finding["location"])
                logger.warning("    Hash: %s", finding["hash"])

                self.alert_manager.create_alert(
                    severity="medium",
                    category="persistence_detection",
                    details=finding,
                )

        # 4. Summary
        summary = self.alert_manager.get_alerts_summary()
        logger.info(separator)
        logger.info("Scan completed")
        logger.info("Total Alerts: %s", summary["total"])
        logger.info("By Severity: %s", dict(summary["by_severity"]))
        logger.info("Critical Alerts: %s", len(summary["recent_critical"]))
        logger.info(separator)

    def _calculate_severity(self, risk_score: int, anomaly_score: int) -> str:
        """Изчислява severity level"""
        total_score = risk_score + anomaly_score

        if total_score >= SEVERITY_CRITICAL:
            return "critical"
        elif total_score >= SEVERITY_HIGH:
            return "high"
        elif total_score >= SEVERITY_MEDIUM:
            return "medium"
        else:
            return "low"

    def generate_report(self) -> str:
        """Генерира security report"""
        # Ако няма алерти, извършваме scan първо
        if not self.alert_manager.alerts:
            logger.info("No alerts found. Running scan before generating report...")
            self.perform_scan()

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
        report.append("By Severity:")
        for severity, count in summary["by_severity"].items():
            report.append(f"  - {severity.upper()}: {count}")
        report.append("")

        if summary["recent_critical"]:
            report.append("CRITICAL ALERTS")
            report.append("-" * 40)
            for alert in summary["recent_critical"]:
                report.append(f"Time: {alert['timestamp']}")
                report.append(f"Category: {alert['category']}")
                report.append(f"Details: {json.dumps(alert['details'], indent=2)}")
                report.append("")

        report.append("=" * 80)

        return "\n".join(report)
