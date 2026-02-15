"""Анализ на поведенчески модели на процеси"""

import logging
from typing import Dict

from config import (
    EXFIL_KEYWORDS,
    INJECTION_KEYWORDS,
    PERSISTENCE_KEYWORDS,
    PRIVILEGE_KEYWORDS,
    SCORE_CODE_INJECTION,
    SCORE_DATA_EXFILTRATION,
    SCORE_PERSISTENCE,
    SCORE_PRIVILEGE_ESCALATION,
)

logger = logging.getLogger("security_monitor.behavioral_analyzer")


class BehavioralAnalyzer:
    """Анализ на поведенчески модели"""

    def analyze_behavior(self, process_info: Dict) -> Dict:
        """Анализира поведението на процес"""
        behavior_analysis = {
            "privilege_escalation": False,
            "data_exfiltration_risk": False,
            "persistence_attempt": False,
            "code_injection_risk": False,
            "anomaly_score": 0,
        }

        cmdline = " ".join(process_info.get("cmdline", []) or []).lower()

        if any(kw in cmdline for kw in PRIVILEGE_KEYWORDS):
            behavior_analysis["privilege_escalation"] = True
            behavior_analysis["anomaly_score"] += SCORE_PRIVILEGE_ESCALATION

        if any(kw in cmdline for kw in EXFIL_KEYWORDS):
            behavior_analysis["data_exfiltration_risk"] = True
            behavior_analysis["anomaly_score"] += SCORE_DATA_EXFILTRATION

        if any(kw in cmdline for kw in PERSISTENCE_KEYWORDS):
            behavior_analysis["persistence_attempt"] = True
            behavior_analysis["anomaly_score"] += SCORE_PERSISTENCE

        if any(kw in cmdline for kw in INJECTION_KEYWORDS):
            behavior_analysis["code_injection_risk"] = True
            behavior_analysis["anomaly_score"] += SCORE_CODE_INJECTION

        return behavior_analysis
