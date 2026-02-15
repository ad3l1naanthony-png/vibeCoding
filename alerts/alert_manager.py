"""Управление на alerts и SIEM integration"""

import json
import logging
import socket
from collections import defaultdict
from datetime import datetime
from typing import Dict

logger = logging.getLogger("security_monitor.alert_manager")


class AlertManager:
    """Управление на alerts и SIEM integration"""

    def __init__(self):
        self.alerts = []

    def create_alert(self, severity: str, category: str, details: Dict):
        """Създава security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "details": details,
            "status": "new",
        }

        self.alerts.append(alert)
        self._log_to_siem(alert)

        return alert

    def _log_to_siem(self, alert: Dict):
        """Логване към SIEM система (mock implementation)"""
        siem_log = {
            "event_type": "python_security_alert",
            "event_data": alert,
            "source": "python_security_monitor",
            "host": socket.gethostname(),
        }

        # Mock: в продукция — API call към Splunk/QRadar/Sentinel
        logger.info("SIEM LOG: %s", json.dumps(siem_log, indent=2))

    def get_alerts_summary(self) -> Dict:
        """Връща резюме на alerts"""
        summary = {
            "total": len(self.alerts),
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "recent_critical": [],
        }

        for alert in self.alerts:
            summary["by_severity"][alert["severity"]] += 1
            summary["by_category"][alert["category"]] += 1

            if alert["severity"] == "critical":
                summary["recent_critical"].append(alert)

        return dict(summary)
