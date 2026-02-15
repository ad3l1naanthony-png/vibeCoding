"""Мониторинг на файловата система за persistence и suspicious files"""

import glob
import hashlib
import logging
import os
from datetime import datetime
from typing import Dict, List

from config import STARTUP_LOCATIONS, WATCHED_EXTENSIONS

logger = logging.getLogger("security_monitor.filesystem_watcher")


class FileSystemWatcher:
    """Мониторинг на файловата система за persistence и suspicious files"""

    def scan_persistence_locations(self) -> List[Dict]:
        """Сканира известни persistence locations"""
        findings = []

        for location_pattern in STARTUP_LOCATIONS:
            try:
                # Използваме glob за правилно резолвиране на wildcards
                resolved_paths = glob.glob(location_pattern)
                for resolved_path in resolved_paths:
                    if not os.path.isdir(resolved_path):
                        continue
                    for file in os.listdir(resolved_path):
                        if file.endswith(WATCHED_EXTENSIONS):
                            file_path = os.path.join(resolved_path, file)
                            findings.append(
                                {
                                    "location": file_path,
                                    "type": "startup_folder",
                                    "file": file,
                                    "hash": self._calculate_hash(file_path),
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
            except OSError as e:
                logger.error("Error scanning %s: %s", location_pattern, e)

        return findings

    def _calculate_hash(self, file_path: str) -> str:
        """Изчислява SHA256 hash на файл"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (OSError, IOError) as e:
            logger.warning("Cannot hash file %s: %s", file_path, e)
            return "N/A"
