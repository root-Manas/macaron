#!/usr/bin/env python3
"""
Security Recon Platform - Main CLI Entry Point
"""
import argparse
import sys
import json
import os
from pathlib import Path
from datetime import datetime

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def setup_logging(verbose: bool = False):
    import logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def cmd_scan(args):
    """Run a scan"""
    from backend.scan_engine import ScanEngine, ScanMode
    
    targets = []
    if args.targets:
        targets = args.targets
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not targets and not args.resume:
        print("Error: Must provide targets or use --resume")
        return 1
    
    # Determine scan mode
    if args.mode == "narrow":
        mode = ScanMode.NARROW
        print(f"[*] NARROW mode: Application-specific scanning")
    else:
        mode = ScanMode.WIDE
        print(f"[*] WIDE mode: Full infrastructure reconnaissance")
    
    # Proxychains
    use_proxy = not args.no_proxy
    if use_proxy:
        print(f"[*] Proxychains: ENABLED")
    else:
        print(f"[*] Proxychains: DISABLED")
    
    print(f"[*] Targets: {', '.join(targets) if targets else 'resuming previous'}")
    print()
    
    engine = ScanEngine(use_proxychains=use_proxy)
    stats = engine.run_scan(targets, mode=mode, resume=args.resume)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(json.dumps(stats, indent=2))
    
    return 0 if stats.get("status") == "completed" else 1


def cmd_add(args):
    """Add targets"""
    from shared.types import Target
    from shared.utils import get_timestamp, is_valid_domain
    
    targets_file = Path("/opt/security-recon/config/targets.txt")
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Load existing
    existing = set()
    if targets_file.exists():
        with open(targets_file) as f:
            existing = set(line.strip() for line in f if line.strip())
    
    # Add new targets
    new_targets = []
    for t in args.targets:
        t = t.strip().lower()
        if t.startswith("http"):
            from shared.utils import extract_domain
            t = extract_domain(t)
        
        if is_valid_domain(t) and t not in existing:
            new_targets.append(t)
            existing.add(t)
    
    if new_targets:
        with open(targets_file, 'a') as f:
            for t in new_targets:
                f.write(f"{t}\n")
        print(f"Added {len(new_targets)} targets: {', '.join(new_targets)}")
    else:
        print("No new targets to add")
    
    return 0


def cmd_list(args):
    """List targets or results"""
    if args.what == "targets":
        targets_file = Path("/opt/security-recon/config/targets.txt")
        if targets_file.exists():
            with open(targets_file) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"Targets ({len(targets)}):")
            for t in targets:
                print(f"  - {t}")
        else:
            print("No targets configured")
    
    elif args.what == "tools":
        from shared.utils import get_installed_tools
        tools = get_installed_tools()
        print("Installed Tools:")
        for tool, installed in sorted(tools.items()):
            status = "✓" if installed else "✗"
            print(f"  [{status}] {tool}")
    
    elif args.what == "scans":
        state_file = Path("/opt/security-recon/state/scan_state.json")
        if state_file.exists():
            with open(state_file) as f:
                state = json.load(f)
            print(f"Last Scan:")
            print(f"  ID: {state.get('scan_id')}")
            print(f"  Status: {state.get('status')}")
            print(f"  Started: {state.get('started_at')}")
            print(f"  Updated: {state.get('last_updated')}")
            print(f"  Targets: {', '.join(state.get('targets', []))}")
            print(f"  Progress: {state.get('current_target_index', 0) + 1}/{len(state.get('targets', []))}")
        else:
            print("No scan history")
    
    elif args.what == "results":
        data_dir = Path("/opt/security-recon/data")
        if data_dir.exists():
            for domain_dir in sorted(data_dir.iterdir()):
                if domain_dir.is_dir():
                    print(f"\n{domain_dir.name}:")
                    
                    subs_file = domain_dir / "subdomains.txt"
                    if subs_file.exists():
                        with open(subs_file) as f:
                            count = len(f.readlines())
                        print(f"  Subdomains: {count}")
                    
                    live_file = domain_dir / "live_hosts.txt"
                    if live_file.exists():
                        with open(live_file) as f:
                            count = len(f.readlines())
                        print(f"  Live Hosts: {count}")
                    
                    ports_file = domain_dir / "ports.txt"
                    if ports_file.exists():
                        with open(ports_file) as f:
                            count = len(f.readlines())
                        print(f"  Open Ports: {count}")
                    
                    vulns_dir = domain_dir / "vulnerabilities"
                    if vulns_dir.exists():
                        nuclei_file = vulns_dir / "nuclei.json"
                        if nuclei_file.exists():
                            with open(nuclei_file) as f:
                                count = len(f.readlines())
                            print(f"  Vulnerabilities: {count}")
    
    return 0


def cmd_status(args):
    """Show daemon and scan status"""
    import subprocess
    
    # Check daemon
    pid_file = Path("/opt/security-recon/state/daemon.pid")
    if pid_file.exists():
        pid = pid_file.read_text().strip()
        try:
            os.kill(int(pid), 0)
            print(f"✓ Daemon running (PID: {pid})")
        except:
            print("✗ Daemon not running (stale PID file)")
    else:
        print("✗ Daemon not running")
    
    # Check scheduler state
    scheduler_state = Path("/opt/security-recon/state/scheduler_state.json")
    if scheduler_state.exists():
        with open(scheduler_state) as f:
            state = json.load(f)
        if state.get("next_run"):
            print(f"  Next scheduled scan: {state.get('next_run')}")
        if state.get("last_run"):
            print(f"  Last scan: {state.get('last_run')}")
    
    # Check current scan
    scan_state = Path("/opt/security-recon/state/scan_state.json")
    if scan_state.exists():
        with open(scan_state) as f:
            state = json.load(f)
        status = state.get("status", "unknown")
        if status in ("running", "paused"):
            print(f"\n⚡ Active scan: {status}")
            print(f"   ID: {state.get('scan_id')}")
            print(f"   Module: {state.get('current_module')}")
            progress = state.get('current_target_index', 0) + 1
            total = len(state.get('targets', []))
            print(f"   Progress: {progress}/{total} targets")
    
    return 0


def cmd_config(args):
    """Configuration management"""
    config_file = Path("/opt/security-recon/config/config.yaml")
    
    if args.action == "show":
        if config_file.exists():
            print(config_file.read_text())
        else:
            print("Config file not found. Run 'recon setup' first.")
    
    elif args.action == "edit":
        import subprocess
        editor = os.environ.get("EDITOR", "nano")
        subprocess.run([editor, str(config_file)])
    
    elif args.action == "set":
        if args.key and args.value:
            import yaml
            
            if config_file.exists():
                with open(config_file) as f:
                    config = yaml.safe_load(f)
            else:
                config = {}
            
            # Navigate to nested key
            keys = args.key.split(".")
            current = config
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            
            # Set value
            try:
                current[keys[-1]] = json.loads(args.value)
            except json.JSONDecodeError:
                current[keys[-1]] = args.value
            
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"Set {args.key} = {args.value}")
    
    elif args.action == "webhook":
        if args.url:
            import yaml
            
            if config_file.exists():
                with open(config_file) as f:
                    config = yaml.safe_load(f)
            else:
                config = {"discord": {}}
            
            if "discord" not in config:
                config["discord"] = {}
            
            config["discord"]["webhook_url"] = args.url
            config["discord"]["enabled"] = True
            
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"Discord webhook configured")
            
            # Test webhook
            if args.test:
                from backend.notifier import SyncDiscordNotifier
                notifier = SyncDiscordNotifier(args.url)
                from shared.types import Severity
                notifier.send_custom("🔧 Test Notification", "Security Recon Platform is configured!", Severity.INFO)
                print("Test notification sent!")
    
    return 0


def cmd_export(args):
    """Export results"""
    data_dir = Path("/opt/security-recon/data")
    output_file = Path(args.output) if args.output else Path(f"recon_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    results = {"domains": {}, "exported_at": datetime.now().isoformat()}
    
    domain = args.domain
    
    if data_dir.exists():
        for domain_dir in data_dir.iterdir():
            if domain_dir.is_dir():
                if domain and domain_dir.name != domain:
                    continue
                
                domain_data = {"name": domain_dir.name}
                
                # Load subdomains
                subs_file = domain_dir / "subdomains.txt"
                if subs_file.exists():
                    with open(subs_file) as f:
                        domain_data["subdomains"] = [l.strip() for l in f if l.strip()]
                
                # Load live hosts
                live_file = domain_dir / "live_hosts.txt"
                if live_file.exists():
                    with open(live_file) as f:
                        domain_data["live_hosts"] = [l.strip() for l in f if l.strip()]
                
                # Load ports
                ports_file = domain_dir / "ports.txt"
                if ports_file.exists():
                    with open(ports_file) as f:
                        domain_data["ports"] = [l.strip() for l in f if l.strip()]
                
                # Load vulnerabilities
                vulns_file = domain_dir / "vulnerabilities" / "nuclei.json"
                if vulns_file.exists():
                    domain_data["vulnerabilities"] = []
                    with open(vulns_file) as f:
                        for line in f:
                            if line.strip():
                                try:
                                    domain_data["vulnerabilities"].append(json.loads(line))
                                except:
                                    pass
                
                results["domains"][domain_dir.name] = domain_data
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Exported to {output_file}")
    return 0


def cmd_daemon(args):
    """Daemon control"""
    import subprocess
    
    script_path = Path(__file__).parent / "scripts" / "daemon.sh"
    
    if not script_path.exists():
        print("Error: daemon.sh not found")
        return 1
    
    result = subprocess.run(["bash", str(script_path), args.action])
    return result.returncode


def cmd_setup(args):
    """Initial setup"""
    import subprocess
    
    print("="*50)
    print("Security Recon Platform Setup")
    print("="*50)
    
    script_path = Path(__file__).parent / "scripts" / "daemon.sh"
    
    if args.install_tools:
        print("\n[1/3] Installing reconnaissance tools...")
        subprocess.run(["bash", str(script_path), "install"])
    
    print("\n[2/3] Setting up environment...")
    subprocess.run(["bash", str(script_path), "setup"])
    
    if args.autostart:
        print("\n[3/3] Configuring auto-start...")
        subprocess.run(["bash", str(script_path), "autostart"])
    
    print("\n" + "="*50)
    print("Setup complete!")
    print("="*50)
    print("\nNext steps:")
    print("  1. Edit config: recon config edit")
    print("  2. Set Discord webhook: recon config webhook --url YOUR_URL")
    print("  3. Add targets: recon add example.com target2.com")
    print("  4. Start scan: recon scan -t example.com")
    print("  5. Or start daemon: recon daemon start")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Security Recon Platform - Automated Reconnaissance Tool"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a scan")
    scan_parser.add_argument("-t", "--targets", nargs="+", help="Target domains/URLs")
    scan_parser.add_argument("-f", "--file", help="File with targets")
    scan_parser.add_argument("-m", "--mode", choices=["wide", "narrow"], default="wide",
                             help="Scan mode: wide (infrastructure) or narrow (application-specific)")
    scan_parser.add_argument("-r", "--resume", action="store_true", help="Resume previous scan")
    scan_parser.add_argument("--no-proxy", action="store_true", help="Disable proxychains")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add targets")
    add_parser.add_argument("targets", nargs="+", help="Targets to add")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List items")
    list_parser.add_argument("what", choices=["targets", "tools", "scans", "results"], help="What to list")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show status")
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Configuration")
    config_parser.add_argument("action", choices=["show", "edit", "set", "webhook"], help="Action")
    config_parser.add_argument("--key", help="Config key (for set)")
    config_parser.add_argument("--value", help="Config value (for set)")
    config_parser.add_argument("--url", help="Webhook URL (for webhook)")
    config_parser.add_argument("--test", action="store_true", help="Test webhook")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export results")
    export_parser.add_argument("-o", "--output", help="Output file")
    export_parser.add_argument("-d", "--domain", help="Specific domain")
    
    # Daemon command
    daemon_parser = subparsers.add_parser("daemon", help="Daemon control")
    daemon_parser.add_argument("action", choices=["start", "stop", "restart", "status", "logs"])
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Initial setup")
    setup_parser.add_argument("--install-tools", action="store_true", help="Install recon tools")
    setup_parser.add_argument("--autostart", action="store_true", help="Configure auto-start")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    setup_logging(args.verbose)
    
    commands = {
        "scan": cmd_scan,
        "add": cmd_add,
        "list": cmd_list,
        "status": cmd_status,
        "config": cmd_config,
        "export": cmd_export,
        "daemon": cmd_daemon,
        "setup": cmd_setup,
    }
    
    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
