"""Мониторинг на Python процеси в системата"""

import fnmatch
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import psutil

from config import (
    MEMORY_THRESHOLD_MB,
    RISK_SCORE_HIGH_MEMORY,
    RISK_SCORE_NETWORK_CONNECTION,
    RISK_SCORE_NON_STANDARD_LOCATION,
    RISK_SCORE_SUSPICIOUS_ARG,
    RISK_SCORE_SUSPICIOUS_CONNECTION,
    RISK_SCORE_SUSPICIOUS_THRESHOLD,
    RISK_SCORE_USER_WRITABLE,
    SUSPICIOUS_ARGS,
    SUSPICIOUS_PORTS,
    USER_WRITABLE_PATTERNS,
    WHITELISTED_PATHS,
)

logger = logging.getLogger("security_monitor.process_monitor")


class ProcessMonitor:
    """Мониторинг на Python процеси в системата"""

    def scan_processes(self) -> List[Dict]:
        """Сканира всички активни Python процеси"""
        python_processes = []

        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "exe", "username", "create_time"]
        ):
            try:
                if proc.info["name"] and "python" in proc.info["name"].lower():
                    process_info = {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": proc.info["exe"],
                        "cmdline": proc.info["cmdline"],
                        "user": proc.info["username"],
                        "started": datetime.fromtimestamp(
                            proc.info["create_time"]
                        ).isoformat(),
                        "suspicious": False,
                        "risk_score": 0,
                        "indicators": [],
                    }

                    self._analyze_process(process_info, proc)
                    python_processes.append(process_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return python_processes

    def _analyze_process(self, info: Dict, proc: psutil.Process):
        """Анализира процес за съмнително поведение"""
        risk_score = 0

        # Проверка на command line arguments
        cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""
        cmdline_lower = cmdline.lower()
        for suspicious_arg in SUSPICIOUS_ARGS:
            if suspicious_arg in cmdline_lower:
                info["indicators"].append(f"Suspicious argument: {suspicious_arg}")
                risk_score += RISK_SCORE_SUSPICIOUS_ARG

        # Проверка на местоположение
        if info["exe"]:
            exe_path = str(Path(info["exe"]))
            is_whitelisted = any(
                fnmatch.fnmatch(exe_path, pattern) for pattern in WHITELISTED_PATHS
            )

            if not is_whitelisted:
                info["indicators"].append(f"Non-standard location: {info['exe']}")
                risk_score += RISK_SCORE_NON_STANDARD_LOCATION

            if self._is_user_writable(Path(info["exe"]).parent):
                info["indicators"].append("Running from user-writable directory")
                risk_score += RISK_SCORE_USER_WRITABLE

        # Проверка на network connections
        try:
            connections = proc.net_connections()
            external_connections = [
                conn
                for conn in connections
                if conn.status == "ESTABLISHED" and conn.raddr
            ]

            if external_connections:
                info["indicators"].append(
                    f"Active network connections: {len(external_connections)}"
                )
                risk_score += RISK_SCORE_NETWORK_CONNECTION * len(external_connections)

                for conn in external_connections:
                    if self._is_suspicious_port(conn):
                        info["indicators"].append(
                            f"Suspicious connection: {conn.raddr}"
                        )
                        risk_score += RISK_SCORE_SUSPICIOUS_CONNECTION

        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        # Проверка на process memory
        try:
            memory_info = proc.memory_info()
            threshold_bytes = MEMORY_THRESHOLD_MB * 1024 * 1024
            if memory_info.rss > threshold_bytes:
                info["indicators"].append(
                    f"High memory usage: {memory_info.rss / 1024 / 1024:.2f}MB"
                )
                risk_score += RISK_SCORE_HIGH_MEMORY
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        info["risk_score"] = risk_score
        info["suspicious"] = risk_score >= RISK_SCORE_SUSPICIOUS_THRESHOLD

    def _is_user_writable(self, path: Path) -> bool:
        """Проверява дали директорията е writable от обикновен потребител"""
        path_str = str(path)
        return any(
            re.match(pattern, path_str, re.IGNORECASE)
            for pattern in USER_WRITABLE_PATTERNS
        )

    def _is_suspicious_port(self, conn) -> bool:
        """Проверява дали connection е към подозрителен порт"""
        return conn.raddr.port in SUSPICIOUS_PORTS
