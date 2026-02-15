"""Policy enforcement engine за корпоративна сигурност"""

import logging
from typing import Dict

from config import POLICIES

logger = logging.getLogger("security_monitor.policy_engine")


class PolicyEngine:
    """Policy enforcement engine"""

    def __init__(self):
        self.policies = dict(POLICIES)

    def evaluate_compliance(self, process_info: Dict, behavior: Dict) -> Dict:
        """Оценява съответствието с политиките"""
        violations = []
        actions = []

        if not self.policies["allow_user_writable_execution"]:
            if any(
                "user-writable" in ind
                for ind in process_info.get("indicators", [])
            ):
                violations.append("Execution from user-writable directory")
                actions.append("TERMINATE_PROCESS")

        if process_info.get("risk_score", 0) > self.policies["max_risk_score"]:
            violations.append(
                f"Risk score {process_info['risk_score']} exceeds "
                f"threshold {self.policies['max_risk_score']}"
            )
            actions.append("QUARANTINE")

        if behavior.get("code_injection_risk") or behavior.get("persistence_attempt"):
            violations.append("Critical behavior detected")
            if self.policies["quarantine_on_critical"]:
                actions.append("IMMEDIATE_QUARANTINE")

        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "recommended_actions": actions,
        }
