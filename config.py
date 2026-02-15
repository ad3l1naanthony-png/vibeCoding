"""
Конфигурация на Python Security Monitoring System
Всички настройки, прагове и константи на едно място
"""

import logging
import sys

# === Process Monitor ===

SUSPICIOUS_ARGS = [
    "base64", "exec", "eval", "compile",
    "__import__", "socket.socket", "subprocess",
    "os.system", "createremotethread", "virtualallocex",
]

WHITELISTED_PATHS = [
    r"C:\Program Files\Python*",
    r"C:\ProgramData\Anaconda*",
    r"C:\Users\*\AppData\Local\Programs\Python\*",
]

USER_WRITABLE_PATTERNS = [
    r".*\\AppData\\Local\\Temp.*",
    r".*\\Downloads.*",
    r".*\\Desktop.*",
    r".*\\Documents.*",
]

SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999}

DNS_TIMEOUT_SECONDS = 2

MEMORY_THRESHOLD_MB = 500

RISK_SCORE_SUSPICIOUS_ARG = 10
RISK_SCORE_NON_STANDARD_LOCATION = 15
RISK_SCORE_USER_WRITABLE = 20
RISK_SCORE_NETWORK_CONNECTION = 5
RISK_SCORE_SUSPICIOUS_CONNECTION = 25
RISK_SCORE_HIGH_MEMORY = 10
RISK_SCORE_SUSPICIOUS_THRESHOLD = 30

# === Behavioral Analyzer ===

PRIVILEGE_KEYWORDS = ["runas", "elevate", "admin", "uac"]
EXFIL_KEYWORDS = ["requests", "urllib", "ftplib", "smtplib", "paramiko"]
PERSISTENCE_KEYWORDS = ["schtasks", "registry", "startup", "run key"]
INJECTION_KEYWORDS = ["ctypes", "virtualalloc", "writeprocessmemory", "createremotethread"]

SCORE_PRIVILEGE_ESCALATION = 25
SCORE_DATA_EXFILTRATION = 15
SCORE_PERSISTENCE = 30
SCORE_CODE_INJECTION = 35

# === File System Watcher ===

STARTUP_LOCATIONS = [
    r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
]

REGISTRY_KEYS = [
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
]

WATCHED_EXTENSIONS = (".py", ".pyw")

# === Alert Manager ===

ALERT_THRESHOLDS = {
    "low": 20,
    "medium": 40,
    "high": 60,
    "critical": 80,
}

# === Policy Engine ===

POLICIES = {
    "allow_user_writable_execution": False,
    "require_digital_signature": True,
    "block_known_malicious_patterns": True,
    "max_risk_score": 50,
    "quarantine_on_critical": True,
}

# === Monitoring ===

DEFAULT_SCAN_INTERVAL = 60

# === Severity Thresholds ===

SEVERITY_CRITICAL = 80
SEVERITY_HIGH = 60
SEVERITY_MEDIUM = 40


# === Logging ===

def setup_logging(level=logging.INFO):
    """Настройка на logging за конзола и файл"""
    logger = logging.getLogger("security_monitor")
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler("security_monitor.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
