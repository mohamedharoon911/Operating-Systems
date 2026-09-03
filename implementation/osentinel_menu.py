"""
OSentinel - Interactive Menu-Driven OS Process Protection System
Provides a complete terminal-based menu interface for process discovery, anomaly detection,
deadlock cycle analysis, quarantine management, autonomous recovery, chaos testing, and policy configuration.
"""
import sys
import os
import time
import subprocess
import webbrowser
import psutil

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from osentinel.config import Config
from osentinel.discovery import ProcessDiscoveryEngine
from osentinel.tree_manager import ProcessTreeManager
from osentinel.anomaly_detector import AnomalyDetector
from osentinel.deadlock_detector import DeadlockDetector
from osentinel.risk_scorer import RiskScorer
from osentinel.quarantine_manager import QuarantineManager
from osentinel.recovery_engine import RecoveryEngine
from osentinel.event_logger import audit_logger
from osentinel.chaos_simulator import chaos_lab

# Enable ANSI escape sequences on Windows
if os.name == 'nt':
    os.system('')

# ANSI Colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_CYAN = "\033[36m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_RED = "\033[31m"
CLR_MAGENTA = "\033[35m"

class OSentinelCLI:
    def __init__(self):
        self.config = Config()
        self.discovery = ProcessDiscoveryEngine()
        self.tree_mgr = ProcessTreeManager(history_limit=self.config.HISTORY_WINDOW_SIZE)
        self.anomaly_det = AnomalyDetector(config=self.config)
        self.deadlock_det = DeadlockDetector()
        self.risk_scorer = RiskScorer(config=self.config)
        self.quarantine_mgr = QuarantineManager()
        self.recovery_engine = RecoveryEngine(quarantine_mgr=self.quarantine_mgr, config=self.config)

    def refresh_state(self):
        """Scans current OS processes and updates tree manager and anomaly evaluations."""
        snapshots = self.discovery.collect_processes()
        self.tree_mgr.update(snapshots)

    def print_header(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{CLR_CYAN}{CLR_BOLD}" + "=" * 80)
        print("           OSentinel - Autonomous OS Process Protection System")
        print("      Process Discovery | Anomaly Detection | Deadlock Analysis | Self-Recovery")
        print("=" * 80 + f"{CLR_RESET}\n")

    def run_main_menu(self):
        while True:
            self.refresh_state()
            self.print_header()

            sys_cpu = psutil.cpu_percent(interval=None)
            sys_mem = psutil.virtual_memory().percent
            total_procs = len(self.tree_mgr.nodes)

            print(f" {CLR_BOLD}SYSTEM OVERVIEW:{CLR_RESET} Active Tasks: {CLR_CYAN}{total_procs}{CLR_RESET} | CPU: {CLR_YELLOW}{sys_cpu}%{CLR_RESET} | RAM: {CLR_MAGENTA}{sys_mem}%{CLR_RESET}")
            print(f" {CLR_BOLD}RECOVERY MODE:{CLR_RESET} {CLR_GREEN}ACTIVE (Autonomous Isolation Enabled){CLR_RESET}\n")

            print(f"{CLR_BOLD}MENU OPTIONS:{CLR_RESET}")
            print(f"  {CLR_CYAN}[1]{CLR_RESET} 📊 View Process List & Telemetry")
            print(f"  {CLR_CYAN}[2]{CLR_RESET} 🌳 View Process Lineage Hierarchy Tree")
            print(f"  {CLR_CYAN}[3]{CLR_RESET} 🚨 Run OS Anomaly Scan & Risk Analysis")
            print(f"  {CLR_CYAN}[4]{CLR_RESET} 🔒 Analyze Wait-For Graph (WFG) & Resource Deadlocks")
            print(f"  {CLR_CYAN}[5]{CLR_RESET} 🛡️ Inspect & Manage Process Quarantine Vault")
            print(f"  {CLR_CYAN}[6]{CLR_RESET} 🚑 Run Autonomous Self-Recovery Engine")
            print(f"  {CLR_CYAN}[7]{CLR_RESET} 🧪 Chaos Anomaly Simulator Lab")
            print(f"  {CLR_CYAN}[8]{CLR_RESET} ⚙️ Configure Protection Rules & Thresholds")
            print(f"  {CLR_CYAN}[9]{CLR_RESET} 📜 View & Export System Audit Trail Log")
            print(f"  {CLR_CYAN}[10]{CLR_RESET} 🌐 Launch Web Dashboard GUI")
            print(f"  {CLR_RED}[0]{CLR_RESET} ❌ Exit OSentinel\n")

            choice = input(f"{CLR_BOLD}Select Option [0-10]: {CLR_RESET}").strip()

            if choice == "1":
                self.view_process_list()
            elif choice == "2":
                self.view_process_tree()
            elif choice == "3":
                self.run_anomaly_scan()
            elif choice == "4":
                self.analyze_deadlocks()
            elif choice == "5":
                self.manage_quarantine_vault()
            elif choice == "6":
                self.run_autonomous_recovery()
            elif choice == "7":
                self.run_chaos_lab()
            elif choice == "8":
                self.configure_policy()
            elif choice == "9":
                self.view_audit_log()
            elif choice == "10":
                self.launch_web_dashboard()
            elif choice == "0":
                print(f"\n{CLR_GREEN}Exiting OSentinel Protection System. Goodbye!{CLR_RESET}")
                break
            else:
                input(f"{CLR_RED}Invalid choice! Press Enter to try again...{CLR_RESET}")

    def view_process_list(self):
        self.print_header()
        print(f"{CLR_BOLD}ACTIVE OS PROCESS LIST (Top 30 by Risk Score):{CLR_RESET}\n")

        deadlock_res = self.deadlock_det.analyze()
        deadlocked_pids = deadlock_res.get("deadlocked_pids", [])

        evaluations = []
        for pid, node in self.tree_mgr.nodes.items():
            anomalies = self.anomaly_det.detect_anomalies(node, self.tree_mgr, deadlocked_pids)
            risk_res = self.risk_scorer.calculate_score(anomalies)
            evaluations.append((node, risk_res))

        evaluations.sort(key=lambda x: x[1].score, reverse=True)

        header = f"{'PID':<8} {'PPID':<8} {'PROCESS NAME':<25} {'CPU %':<8} {'RAM (MB)':<10} {'RISK':<8} {'TIER':<12}"
        print(CLR_BOLD + header + CLR_RESET)
        print("-" * 80)

        for node, risk_res in evaluations[:30]:
            snap = node.snapshot
            color = CLR_GREEN
            if risk_res.tier == "WARNING": color = CLR_YELLOW
            elif risk_res.tier == "SUSPICIOUS": color = CLR_MAGENTA
            elif risk_res.tier == "CRITICAL": color = CLR_RED

            ram_mb = round(snap.memory_rss_bytes / (1024 * 1024), 1)
            row = f"{snap.pid:<8} {snap.ppid or 'N/A':<8} {snap.name[:24]:<25} {snap.cpu_percent:<8.1f} {ram_mb:<10.1f} {risk_res.score:<8} {color}{risk_res.tier:<12}{CLR_RESET}"
            print(row)

        print("\nPress Enter to inspect a process PID, or 'b' to return to Main Menu.")
        pid_in = input("Enter PID to inspect (or Enter to go back): ").strip()
        if pid_in.isdigit():
            self.inspect_process(int(pid_in))

    def inspect_process(self, pid: int):
        self.print_header()
        node = self.tree_mgr.get_node(pid)
        if not node:
            input(f"{CLR_RED}PID {pid} not found! Press Enter to continue...{CLR_RESET}")
            return

        snap = node.snapshot
        deadlock_res = self.deadlock_det.analyze()
        anomalies = self.anomaly_det.detect_anomalies(node, self.tree_mgr, deadlock_res.get("deadlocked_pids", []))
        risk_res = self.risk_scorer.calculate_score(anomalies)

        print(f"{CLR_BOLD}PROCESS INSPECTION REPORT - PID {pid}{CLR_RESET}\n")
        print(f"  Name:             {CLR_CYAN}{snap.name}{CLR_RESET}")
        print(f"  Parent PID:       {snap.ppid}")
        print(f"  Status:           {snap.status}")
        print(f"  CPU Usage:        {snap.cpu_percent}%")
        print(f"  Memory RSS:       {round(snap.memory_rss_bytes / (1024*1024), 2)} MB")
        print(f"  Threads Count:    {snap.num_threads}")
        print(f"  Children Count:   {snap.num_children}")
        print(f"  Lifetime:         {round(snap.lifetime_seconds, 1)} seconds")
        print(f"  Command Line:     {snap.cmdline}")
        print(f"  Risk Score:       {CLR_BOLD}{risk_res.score} / 100 ({risk_res.tier}){CLR_RESET}\n")

        print(f"{CLR_BOLD}ANOMALY REASONS:{CLR_RESET}")
        if anomalies:
            for a in anomalies:
                print(f"  • {CLR_RED}{a.anomaly_type}{CLR_RESET}: {a.description}")
        else:
            print(f"  {CLR_GREEN}• Operating normally. No abnormal flags detected.{CLR_RESET}")

        print(f"\n{CLR_BOLD}ACTIONS:{CLR_RESET}")
        print("  [1] Throttle / Quarantine Process (Lower Priority & Affinity)")
        print("  [2] Terminate Process")
        print("  [3] Release Quarantine")
        print("  [0] Back")
        act = input("\nSelect Action [0-3]: ").strip()

        if act == "1":
            res = self.quarantine_mgr.quarantine_process(pid, action_type="THROTTLE", reason="Manual CLI Action")
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif act == "2":
            try:
                p = psutil.Process(pid)
                p.terminate()
                print(f"\n{CLR_GREEN}Process PID {pid} terminated successfully.{CLR_RESET}")
                audit_logger.log_event("MANUAL_TERMINATION", "RECOVERY", pid, snap.name, f"Terminated PID {pid}")
            except Exception as e:
                print(f"\n{CLR_RED}Failed to terminate PID {pid}: {e}{CLR_RESET}")
            time.sleep(1.5)
        elif act == "3":
            res = self.quarantine_mgr.release_quarantine(pid)
            print(f"\n{res['message']}")
            time.sleep(1.5)

    def view_process_tree(self):
        self.print_header()
        print(f"{CLR_BOLD}PROCESS HIERARCHY TREE (Parent - Child Lineage):{CLR_RESET}\n")

        tree_nodes = self.tree_mgr.build_tree_structure()

        def print_tree(nodes, depth=0):
            for n in nodes[:25]: # limit output
                indent = "  " * depth + ("└── " if depth > 0 else "• ")
                print(f"{indent}{CLR_CYAN}{n['name']}{CLR_RESET} (PID {n['pid']}, PPID {n['ppid'] or 'N/A'}) [CPU {n['cpu_percent']}%, RAM {n['memory_rss_mb']}MB]")
                if n.get("children"):
                    print_tree(n["children"], depth + 1)

        print_tree(tree_nodes)
        input(f"\n{CLR_BOLD}Press Enter to return to main menu...{CLR_RESET}")

    def run_anomaly_scan(self):
        self.print_header()
        print(f"{CLR_BOLD}RUNNING OS ANOMALY DETECTION SCAN...{CLR_RESET}\n")

        deadlock_res = self.deadlock_det.analyze()
        deadlocked_pids = deadlock_res.get("deadlocked_pids", [])

        flagged = []
        for pid, node in self.tree_mgr.nodes.items():
            anomalies = self.anomaly_det.detect_anomalies(node, self.tree_mgr, deadlocked_pids)
            if anomalies:
                risk_res = self.risk_scorer.calculate_score(anomalies)
                flagged.append((node, risk_res, anomalies))

        flagged.sort(key=lambda x: x[1].score, reverse=True)

        print(f"Found {CLR_RED}{len(flagged)}{CLR_RESET} process(es) exhibiting OS anomalies:\n")
        for node, risk_res, anomalies in flagged:
            snap = node.snapshot
            print(f"• {CLR_BOLD}{snap.name}{CLR_RESET} (PID {snap.pid}) - Risk Score: {CLR_RED}{risk_res.score}/100 ({risk_res.tier}){CLR_RESET}")
            for a in anomalies:
                print(f"    - [{a.anomaly_type}] {a.description}")
            print()

        input(f"{CLR_BOLD}Press Enter to return to main menu...{CLR_RESET}")

    def analyze_deadlocks(self):
        self.print_header()
        print(f"{CLR_BOLD}WAIT-FOR GRAPH (WFG) DEADLOCK ANALYZER:{CLR_RESET}\n")

        deadlock_res = self.deadlock_det.analyze()
        count = deadlock_res.get("deadlock_count", 0)

        if count == 0:
            print(f"{CLR_GREEN}No active Wait-For Graph resource deadlocks detected.{CLR_RESET}")
        else:
            print(f"{CLR_RED}{CLR_BOLD}DETECTED {count} DEADLOCK CYCLE(S):{CLR_RESET}\n")
            for idx, c in enumerate(deadlock_res.get("cycles", []), 1):
                print(f" Cycle #{idx}: {c['description']}")
                print(f" Deadlocked PIDs involved: {c['pids']}")

        print("\nOptions: [1] Trigger Chaos Deadlock Pair, [2] Clear WFG, [0] Back")
        opt = input("Select: ").strip()
        if opt == "1":
            res = chaos_lab.spawn_deadlock_pair(self.deadlock_det)
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "2":
            self.deadlock_det.clear_all()
            print(f"\n{CLR_GREEN}Cleared Wait-For Graph.{CLR_RESET}")
            time.sleep(1.5)

    def manage_quarantine_vault(self):
        self.print_header()
        print(f"{CLR_BOLD}PROCESS QUARANTINE VAULT:{CLR_RESET}\n")

        quarantined = self.quarantine_mgr.get_quarantined_list()
        if not quarantined:
            print(f"{CLR_GREEN}No processes currently isolated in Quarantine.{CLR_RESET}")
        else:
            for q in quarantined:
                print(f"• {CLR_BOLD}{q['process_name']}{CLR_RESET} (PID {q['pid']}) - Action: {q['action_type']} | Duration: {q['duration_seconds']}s | Reason: {q['reason']}")

        input(f"\n{CLR_BOLD}Press Enter to return to main menu...{CLR_RESET}")

    def run_autonomous_recovery(self):
        self.print_header()
        print(f"{CLR_BOLD}RUNNING AUTONOMOUS SELF-RECOVERY ENGINE...{CLR_RESET}\n")

        deadlock_res = self.deadlock_det.analyze()
        deadlocked_pids = deadlock_res.get("deadlocked_pids", [])

        recovered_count = 0
        for pid, node in list(self.tree_mgr.nodes.items()):
            anomalies = self.anomaly_det.detect_anomalies(node, self.tree_mgr, deadlocked_pids)
            risk_res = self.risk_scorer.calculate_score(anomalies)

            is_simulated = chaos_lab.is_simulated_pid(pid)
            if risk_res.score >= self.config.AUTO_QUARANTINE_THRESHOLD:
                res = self.recovery_engine.execute_recovery(node, risk_res, is_simulated=is_simulated, force_auto=True)
                if res:
                    recovered_count += 1
                    print(f"  • {CLR_GREEN}{res['message']}{CLR_RESET}")

        if recovered_count == 0:
            print(f"{CLR_GREEN}All processes healthy. No autonomous recovery actions required.{CLR_RESET}")

        input(f"\n{CLR_BOLD}Press Enter to return to main menu...{CLR_RESET}")

    def run_chaos_lab(self):
        self.print_header()
        print(f"{CLR_BOLD}CHAOS ANOMALY SIMULATOR LAB:{CLR_RESET}\n")
        print("  [1] Spawn Orphan Process Scenario")
        print("  [2] Spawn Runaway CPU Load Process Scenario")
        print("  [3] Spawn Memory Leak Scenario")
        print("  [4] Spawn Process Explosion (Fork Bomb) Scenario")
        print("  [5] Spawn Wait-For Graph Deadlock Pair Scenario")
        print("  [6] Cleanup All Chaos Simulations")
        print("  [0] Back")

        opt = input("\nSelect Scenario [0-6]: ").strip()
        if opt == "1":
            res = chaos_lab.spawn_orphan()
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "2":
            res = chaos_lab.spawn_runaway_cpu()
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "3":
            res = chaos_lab.spawn_memory_leak()
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "4":
            res = chaos_lab.spawn_process_explosion()
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "5":
            res = chaos_lab.spawn_deadlock_pair(self.deadlock_det)
            print(f"\n{res['message']}")
            time.sleep(1.5)
        elif opt == "6":
            res = chaos_lab.cleanup_all()
            self.deadlock_det.clear_all()
            print(f"\n{res['message']}")
            time.sleep(1.5)

    def configure_policy(self):
        self.print_header()
        print(f"{CLR_BOLD}CONFIGURE OSENTINEL PROTECTION POLICIES:{CLR_RESET}\n")
        print(f"  Current Runaway CPU Threshold:  {self.config.RUNAWAY_CPU_THRESHOLD_PCT}%")
        print(f"  Current Memory Leak Growth:    {self.config.MEMORY_LEAK_GROWTH_RATE_MB_PER_SEC} MB/s")
        print(f"  Current Process Explosion Limit:{self.config.PROCESS_EXPLOSION_CHILD_COUNT} Children\n")

        val = input("Enter new Runaway CPU Threshold % (or Enter to keep current): ").strip()
        if val.isdigit():
            self.config.RUNAWAY_CPU_THRESHOLD_PCT = float(val)
            print(f"{CLR_GREEN}Updated Runaway CPU Threshold to {val}%{CLR_RESET}")
            time.sleep(1.5)

    def view_audit_log(self):
        self.print_header()
        print(f"{CLR_BOLD}SYSTEM AUDIT TRAIL LOG:{CLR_RESET}\n")

        events = audit_logger.get_events(limit=20)
        for e in events:
            time_str = e['timestamp'].split("T")[1][:8]
            print(f"[{time_str}] [{e['severity']}] {e['event_type']} - PID {e['pid'] or 'N/A'}: {e['message']}")

        input(f"\n{CLR_BOLD}Press Enter to return to main menu...{CLR_RESET}")

    def launch_web_dashboard(self):
        print(f"\n{CLR_CYAN}Launching Web Dashboard on http://localhost:8000 ...{CLR_RESET}")
        try:
            webbrowser.open("http://localhost:8000")
        except Exception as e:
            print(f"{CLR_RED}Failed to open browser: {e}{CLR_RESET}")
        time.sleep(1.5)


if __name__ == "__main__":
    cli = OSentinelCLI()
    cli.run_main_menu()
