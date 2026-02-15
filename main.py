"""
Python Security Monitoring System
Система за мониторинг и детектиране на съмнителни Python-базирани приложения
в корпоративна среда
"""

from datetime import datetime

from config import setup_logging
from system import SecurityMonitoringSystem

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║  Python Security Monitoring System                              ║
║  Корпоративна киберсигурност — Мониторинг на Python процеси     ║
╚══════════════════════════════════════════════════════════════════╝
"""


def main():
    """Main entry point"""
    logger = setup_logging()
    print(BANNER)

    system = SecurityMonitoringSystem()

    print("Options:")
    print("  1. Perform single scan")
    print("  2. Start continuous monitoring (60 sec interval)")
    print("  3. Generate report")

    try:
        choice = input("\nSelect option (1-3): ").strip()

        if choice == "1":
            system.perform_scan()
        elif choice == "2":
            system.start_monitoring(interval=60)
        elif choice == "3":
            report = system.generate_report()
            print(report)

            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report)
            logger.info("Report saved to: %s", filename)
        else:
            print("[!] Invalid option")

    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    except Exception as e:
        logger.error("Error: %s", e)


if __name__ == "__main__":
    main()
