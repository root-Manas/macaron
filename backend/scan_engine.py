"""
Scan Engine - Orchestrates all reconnaissance tools with chained pipelines
Supports WIDE (infrastructure) and NARROW (application-specific) scan modes
"""
import asyncio
import json
import subprocess
import tempfile
import shutil
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
import logging
import signal
import re

# Proper imports without sys.path manipulation
from shared.types import Config, ScanStatus, ScanState, Subdomain, Port, HttpEndpoint, Vulnerability, Severity
from shared.utils import (
    get_timestamp, ensure_dir, deduplicate_subdomains, check_tool_installed,
    run_command, parse_ndjson, RateLimiter, ProgressTracker, generate_scan_id
)
from backend.notifier import SyncDiscordNotifier

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Scan modes"""
    WIDE = "wide"      # Full infrastructure recon - subdomain enum, port scan, everything
    NARROW = "narrow"  # Application-specific - focused on a single app/URL


@dataclass
class ScanContext:
    """Context passed through the scan pipeline"""
    target: str
    mode: ScanMode
    data_dir: Path
    
    # Discovered assets (chained between stages)
    subdomains: Set[str] = field(default_factory=set)
    resolved_hosts: Dict[str, List[str]] = field(default_factory=dict)  # subdomain -> IPs
    live_hosts: Set[str] = field(default_factory=set)  # URLs that responded
    open_ports: Dict[str, List[int]] = field(default_factory=dict)  # host -> ports
    urls: Set[str] = field(default_factory=set)  # All discovered URLs
    js_files: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    technologies: Dict[str, List[str]] = field(default_factory=dict)  # host -> techs
    vulnerabilities: List[Dict] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    
    # Tracking
    errors: List[str] = field(default_factory=list)
    tool_results: Dict[str, Any] = field(default_factory=dict)


class ScanEngine:
    """
    Main scan orchestrator with chained pipeline execution
    
    Pipeline for WIDE mode:
    1. Subdomain Discovery (subfinder, amass, assetfinder, crt.sh, chaos, findomain, etc.)
    2. DNS Resolution (dnsx, massdns)
    3. Port Scanning (naabu, masscan)
    4. HTTP Probing (httpx with tech detection)
    5. URL Discovery (gau, waymore, katana, waybackurls)
    6. JS Analysis (getJS, linkfinder, secretfinder)
    7. Screenshots (gowitness, eyewitness)
    8. Vulnerability Scanning (nuclei)
    
    Pipeline for NARROW mode:
    1. HTTP Probing on target
    2. Crawling (katana, hakrawler)
    3. URL Discovery (gau, waymore)
    4. JS Analysis
    5. Content Discovery (ffuf, feroxbuster)
    6. Screenshots
    7. Vulnerability Scanning (nuclei with specific templates)
    """
    
    def __init__(self, config_override: Dict[str, Any] = None, use_proxychains: bool = True):
        self.config = Config()
        self.config_override = config_override or {}
        self.notifier = SyncDiscordNotifier()
        self.state: Optional[ScanState] = None
        self.running = False
        self.paused = False
        self.use_proxychains = use_proxychains and check_tool_installed("proxychains4")
        
        self._executor = ThreadPoolExecutor(max_workers=self.config.get("general.max_concurrent_scans", 5))
        
        # Setup directories
        self.base_data_dir = Path(self.config.get("general.data_dir", "/opt/security-recon/data"))
        self.logs_dir = Path(self.config.get("general.logs_dir", "/opt/security-recon/logs"))
        ensure_dir(self.base_data_dir)
        ensure_dir(self.logs_dir)
        
        # Rate limiter
        self.rate_limiter = RateLimiter(self.config.get("rate_limits.global_requests_per_second", 100))
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
    
    def _handle_interrupt(self, signum, frame):
        """Handle interrupt signals gracefully"""
        logger.info("Interrupt received, saving state and stopping...")
        self.paused = True
        self.running = False
        self._save_state()
    
    def _cmd(self, cmd: List[str], timeout: int = 300) -> tuple:
        """Run command with optional proxychains"""
        if self.use_proxychains:
            cmd = ["proxychains4", "-q"] + cmd
        return run_command(cmd, timeout=timeout, use_proxychains=False)
    
    def _save_state(self):
        """Save current scan state for resume"""
        if self.state:
            state_file = Path(self.config.get("general.state_file", "/opt/security-recon/state/scan_state.json"))
            ensure_dir(state_file.parent)
            with open(state_file, 'w') as f:
                json.dump({
                    "scan_id": self.state.scan_id,
                    "targets": self.state.targets,
                    "current_target_index": self.state.current_target_index,
                    "current_module": self.state.current_module,
                    "current_tool": self.state.current_tool,
                    "completed_modules": self.state.completed_modules,
                    "status": self.state.status.value,
                    "started_at": self.state.started_at,
                    "last_updated": get_timestamp(),
                    "error_count": self.state.error_count,
                    "resume_data": self.state.resume_data
                }, f, indent=2)
    
    def _load_state(self) -> Optional[ScanState]:
        """Load saved scan state"""
        state_file = Path(self.config.get("general.state_file", "/opt/security-recon/state/scan_state.json"))
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
                return ScanState(
                    scan_id=data["scan_id"],
                    targets=data["targets"],
                    current_target_index=data["current_target_index"],
                    current_module=data.get("current_module"),
                    current_tool=data.get("current_tool"),
                    completed_modules=data.get("completed_modules", {}),
                    status=ScanStatus(data["status"]),
                    started_at=data.get("started_at"),
                    last_updated=data.get("last_updated"),
                    error_count=data.get("error_count", 0),
                    resume_data=data.get("resume_data", {})
                )
        return None
    
    def run_scan(
        self, 
        targets: List[str], 
        mode: ScanMode = ScanMode.WIDE,
        resume: bool = False
    ) -> Dict[str, Any]:
        """
        Run reconnaissance scan on targets
        
        Args:
            targets: List of domains or URLs
            mode: WIDE for infrastructure, NARROW for application-specific
            resume: Resume from previous state
        """
        start_time = datetime.now()
        
        # Check for resume
        if resume:
            saved_state = self._load_state()
            if saved_state and saved_state.status in (ScanStatus.RUNNING, ScanStatus.PAUSED):
                self.state = saved_state
                targets = self.state.targets
                logger.info(f"Resuming scan {self.state.scan_id}")
            else:
                resume = False
        
        if not resume:
            self.state = ScanState(
                scan_id=generate_scan_id(targets),
                targets=targets,
                started_at=get_timestamp()
            )
        
        self.running = True
        self.state.status = ScanStatus.RUNNING
        
        # Notify
        try:
            self.notifier.notify_scan_start(targets, [f"{mode.value} mode"])
        except Exception as e:
            logger.warning(f"Failed to send scan start notification: {e}")
        
        all_stats = {
            "scan_id": self.state.scan_id,
            "mode": mode.value,
            "targets_processed": 0,
            "total_targets": len(targets),
            "subdomains": 0,
            "live_hosts": 0,
            "urls": 0,
            "ports": 0,
            "vulnerabilities": 0,
            "errors": 0
        }
        
        try:
            for i, target in enumerate(targets[self.state.current_target_index:], self.state.current_target_index):
                if not self.running:
                    break
                
                self.state.current_target_index = i
                logger.info(f"[{i+1}/{len(targets)}] Processing: {target} ({mode.value} mode)")
                
                # Create scan context
                target_dir = self.base_data_dir / self._sanitize_target(target)
                ensure_dir(target_dir)
                
                ctx = ScanContext(
                    target=target,
                    mode=mode,
                    data_dir=target_dir
                )
                
                # Run pipeline based on mode
                if mode == ScanMode.WIDE:
                    ctx = self._run_wide_pipeline(ctx)
                else:
                    ctx = self._run_narrow_pipeline(ctx)
                
                # Update stats
                all_stats["subdomains"] += len(ctx.subdomains)
                all_stats["live_hosts"] += len(ctx.live_hosts)
                all_stats["urls"] += len(ctx.urls)
                all_stats["ports"] += sum(len(ports) for ports in ctx.open_ports.values())
                all_stats["vulnerabilities"] += len(ctx.vulnerabilities)
                all_stats["errors"] += len(ctx.errors)
                all_stats["targets_processed"] += 1
                
                # Save results
                self._save_results(ctx)
                self._save_state()
            
            if self.running:
                self.state.status = ScanStatus.COMPLETED
            else:
                self.state.status = ScanStatus.PAUSED
                
        except Exception as e:
            self.state.status = ScanStatus.FAILED
            logger.error(f"Scan failed: {e}")
            self.state.error_count += 1
            try:
                self.notifier.notify_error(str(e), "Scan Engine")
            except:
                pass
        finally:
            self._save_state()
            self.running = False
        
        # Calculate duration
        duration = datetime.now() - start_time
        all_stats["duration"] = str(duration)
        all_stats["status"] = self.state.status.value
        
        # Notify completion
        try:
            self.notifier.notify_scan_complete(all_stats)
        except Exception as e:
            logger.warning(f"Failed to send scan complete notification: {e}")
        
        return all_stats
    
    def _sanitize_target(self, target: str) -> str:
        """Sanitize target for use as directory name"""
        return re.sub(r'[^\w\-.]', '_', target.replace("https://", "").replace("http://", "").split("/")[0])
    
    # ==================== WIDE MODE PIPELINE ====================
    
    def _run_wide_pipeline(self, ctx: ScanContext) -> ScanContext:
        """
        Full infrastructure reconnaissance pipeline
        Each stage chains into the next
        """
        logger.info(f"[WIDE] Starting infrastructure recon for {ctx.target}")
        
        # Stage 1: Subdomain Discovery
        ctx = self._stage_subdomain_discovery(ctx)
        if not self.running:
            return ctx
        
        # Stage 2: DNS Resolution
        ctx = self._stage_dns_resolution(ctx)
        if not self.running:
            return ctx
        
        # Stage 3: Port Scanning
        ctx = self._stage_port_scanning(ctx)
        if not self.running:
            return ctx
        
        # Stage 4: HTTP Probing + Tech Detection
        ctx = self._stage_http_probing(ctx)
        if not self.running:
            return ctx
        
        # Stage 5: URL Discovery
        ctx = self._stage_url_discovery(ctx)
        if not self.running:
            return ctx
        
        # Stage 6: JS Analysis
        ctx = self._stage_js_analysis(ctx)
        if not self.running:
            return ctx
        
        # Stage 7: Screenshots
        ctx = self._stage_screenshots(ctx)
        if not self.running:
            return ctx
        
        # Stage 8: Vulnerability Scanning
        ctx = self._stage_vuln_scanning(ctx)
        
        return ctx
    
    # ==================== NARROW MODE PIPELINE ====================
    
    def _run_narrow_pipeline(self, ctx: ScanContext) -> ScanContext:
        """
        Application-specific reconnaissance pipeline
        Focused on a single target URL/domain
        """
        logger.info(f"[NARROW] Starting application recon for {ctx.target}")
        
        # Add target as the only "subdomain"
        ctx.subdomains.add(ctx.target)
        
        # Stage 1: HTTP Probing
        ctx = self._stage_http_probing(ctx)
        if not self.running:
            return ctx
        
        # Stage 2: Crawling
        ctx = self._stage_crawling(ctx)
        if not self.running:
            return ctx
        
        # Stage 3: URL Discovery
        ctx = self._stage_url_discovery(ctx)
        if not self.running:
            return ctx
        
        # Stage 4: JS Analysis
        ctx = self._stage_js_analysis(ctx)
        if not self.running:
            return ctx
        
        # Stage 5: Content Discovery
        ctx = self._stage_content_discovery(ctx)
        if not self.running:
            return ctx
        
        # Stage 6: Screenshots
        ctx = self._stage_screenshots(ctx)
        if not self.running:
            return ctx
        
        # Stage 7: Vulnerability Scanning (focused templates)
        ctx = self._stage_vuln_scanning(ctx, focused=True)
        
        return ctx
    
    # ==================== PIPELINE STAGES ====================
    
    def _stage_subdomain_discovery(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 1: Subdomain Discovery
        Tools: subfinder, amass, assetfinder, findomain, crt.sh, chaos-client, etc.
        """
        logger.info(f"[Stage 1] Subdomain Discovery for {ctx.target}")
        self.state.current_module = "subdomain_discovery"
        
        all_subs = set()
        
        # Subfinder
        if check_tool_installed("subfinder"):
            self.state.current_tool = "subfinder"
            logger.info("  Running subfinder...")
            subs = self._run_subfinder(ctx.target)
            all_subs.update(subs)
            logger.info(f"  subfinder: {len(subs)} subdomains")
        
        # Amass (passive)
        if check_tool_installed("amass"):
            self.state.current_tool = "amass"
            logger.info("  Running amass (passive)...")
            subs = self._run_amass(ctx.target)
            all_subs.update(subs)
            logger.info(f"  amass: {len(subs)} subdomains")
        
        # Assetfinder
        if check_tool_installed("assetfinder"):
            self.state.current_tool = "assetfinder"
            logger.info("  Running assetfinder...")
            subs = self._run_assetfinder(ctx.target)
            all_subs.update(subs)
            logger.info(f"  assetfinder: {len(subs)} subdomains")
        
        # Findomain
        if check_tool_installed("findomain"):
            self.state.current_tool = "findomain"
            logger.info("  Running findomain...")
            subs = self._run_findomain(ctx.target)
            all_subs.update(subs)
            logger.info(f"  findomain: {len(subs)} subdomains")
        
        # crt.sh (no tool needed, uses curl/API)
        logger.info("  Querying crt.sh...")
        subs = self._run_crtsh(ctx.target)
        all_subs.update(subs)
        logger.info(f"  crt.sh: {len(subs)} subdomains")
        
        # Chaos client
        if check_tool_installed("chaos"):
            self.state.current_tool = "chaos"
            api_key = self.config.get_api_key("chaos")
            if api_key:
                logger.info("  Running chaos-client...")
                subs = self._run_chaos(ctx.target, api_key)
                all_subs.update(subs)
                logger.info(f"  chaos: {len(subs)} subdomains")
        
        # github-subdomains (if installed)
        if check_tool_installed("github-subdomains"):
            self.state.current_tool = "github-subdomains"
            github_token = self.config.get_api_key("github")
            if github_token:
                logger.info("  Running github-subdomains...")
                subs = self._run_github_subdomains(ctx.target, github_token)
                all_subs.update(subs)
        
        # Deduplicate and filter
        ctx.subdomains = set(deduplicate_subdomains(list(all_subs)))
        
        # Filter to only include target domain
        ctx.subdomains = {s for s in ctx.subdomains if ctx.target in s}
        
        logger.info(f"[Stage 1] Complete: {len(ctx.subdomains)} unique subdomains")
        
        # Save intermediate results
        self._save_list(ctx.data_dir / "subdomains.txt", ctx.subdomains)
        
        # Notify new subdomains
        if ctx.subdomains:
            try:
                self.notifier.notify_new_subdomains(ctx.target, list(ctx.subdomains)[:50])
            except Exception as e:
                logger.warning(f"Failed to send subdomain notification: {e}")
        
        return ctx
    
    def _stage_dns_resolution(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 2: DNS Resolution
        Tools: dnsx, massdns
        """
        if not ctx.subdomains:
            return ctx
        
        logger.info(f"[Stage 2] DNS Resolution for {len(ctx.subdomains)} subdomains")
        self.state.current_module = "dns_resolution"
        
        # dnsx
        if check_tool_installed("dnsx"):
            self.state.current_tool = "dnsx"
            logger.info("  Running dnsx...")
            resolved = self._run_dnsx(list(ctx.subdomains))
            ctx.resolved_hosts = resolved
            logger.info(f"  dnsx: {len(resolved)} hosts resolved")
        
        # Save resolved
        self._save_list(ctx.data_dir / "resolved.txt", [
            f"{host}: {', '.join(ips)}" for host, ips in ctx.resolved_hosts.items()
        ])
        
        return ctx
    
    def _stage_port_scanning(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 3: Port Scanning
        Tools: naabu, masscan
        Smart scanning - uses resolved IPs
        """
        if not ctx.resolved_hosts and not ctx.subdomains:
            return ctx
        
        logger.info(f"[Stage 3] Port Scanning")
        self.state.current_module = "port_scanning"
        
        # Get hosts to scan (prefer resolved, fallback to subdomains)
        hosts = list(ctx.resolved_hosts.keys()) if ctx.resolved_hosts else list(ctx.subdomains)
        
        # Naabu (fast, reliable)
        if check_tool_installed("naabu"):
            self.state.current_tool = "naabu"
            logger.info(f"  Running naabu on {len(hosts)} hosts...")
            ports = self._run_naabu(hosts)
            ctx.open_ports = ports
            total_ports = sum(len(p) for p in ports.values())
            logger.info(f"  naabu: {total_ports} open ports found")
        
        # Save ports
        port_lines = [f"{host}:{port}" for host, ports in ctx.open_ports.items() for port in ports]
        self._save_list(ctx.data_dir / "ports.txt", port_lines)
        
        return ctx
    
    def _stage_http_probing(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 4: HTTP Probing with Technology Detection
        Tools: httpx
        """
        if not ctx.subdomains:
            return ctx
        
        logger.info(f"[Stage 4] HTTP Probing + Tech Detection")
        self.state.current_module = "http_probing"
        
        # Build targets - include port-specific if available
        targets = set()
        for sub in ctx.subdomains:
            targets.add(sub)
            if sub in ctx.open_ports:
                for port in ctx.open_ports[sub]:
                    if port not in (80, 443):
                        targets.add(f"{sub}:{port}")
        
        # httpx
        if check_tool_installed("httpx"):
            self.state.current_tool = "httpx"
            logger.info(f"  Running httpx on {len(targets)} targets...")
            live, techs = self._run_httpx(list(targets))
            ctx.live_hosts = set(live)
            ctx.technologies = techs
            logger.info(f"  httpx: {len(ctx.live_hosts)} live hosts")
        
        # Save live hosts
        self._save_list(ctx.data_dir / "live_hosts.txt", ctx.live_hosts)
        
        # Save technologies
        tech_lines = [f"{host}: {', '.join(techs)}" for host, techs in ctx.technologies.items()]
        self._save_list(ctx.data_dir / "technologies.txt", tech_lines)
        
        return ctx
    
    def _stage_url_discovery(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 5: URL Discovery from archives and crawling
        Tools: gau, waymore, waybackurls, katana
        """
        if not ctx.live_hosts and not ctx.subdomains:
            return ctx
        
        logger.info(f"[Stage 5] URL Discovery")
        self.state.current_module = "url_discovery"
        
        all_urls = set()
        targets = list(ctx.live_hosts) if ctx.live_hosts else list(ctx.subdomains)[:20]
        
        # GAU (GetAllUrls)
        if check_tool_installed("gau"):
            self.state.current_tool = "gau"
            logger.info("  Running gau...")
            urls = self._run_gau(targets)
            all_urls.update(urls)
            logger.info(f"  gau: {len(urls)} URLs")
        
        # Waymore
        if check_tool_installed("waymore"):
            self.state.current_tool = "waymore"
            logger.info("  Running waymore...")
            urls = self._run_waymore(ctx.target)
            all_urls.update(urls)
            logger.info(f"  waymore: {len(urls)} URLs")
        
        # Waybackurls
        if check_tool_installed("waybackurls"):
            self.state.current_tool = "waybackurls"
            logger.info("  Running waybackurls...")
            urls = self._run_waybackurls(ctx.target)
            all_urls.update(urls)
            logger.info(f"  waybackurls: {len(urls)} URLs")
        
        # Katana (modern crawler)
        if check_tool_installed("katana") and ctx.live_hosts:
            self.state.current_tool = "katana"
            logger.info("  Running katana...")
            urls = self._run_katana(list(ctx.live_hosts)[:10])
            all_urls.update(urls)
            logger.info(f"  katana: {len(urls)} URLs")
        
        ctx.urls = all_urls
        
        # Extract JS files
        ctx.js_files = {u for u in all_urls if u.endswith('.js') or '.js?' in u}
        
        logger.info(f"[Stage 5] Complete: {len(ctx.urls)} URLs, {len(ctx.js_files)} JS files")
        
        # Save URLs
        self._save_list(ctx.data_dir / "urls.txt", ctx.urls)
        self._save_list(ctx.data_dir / "js_files.txt", ctx.js_files)
        
        return ctx
    
    def _stage_crawling(self, ctx: ScanContext) -> ScanContext:
        """
        Deep crawling for NARROW mode
        Tools: katana, hakrawler
        """
        if not ctx.live_hosts:
            return ctx
        
        logger.info(f"[Stage] Deep Crawling")
        self.state.current_module = "crawling"
        
        all_urls = set(ctx.urls)
        
        # Katana with depth
        if check_tool_installed("katana"):
            self.state.current_tool = "katana"
            logger.info("  Running katana (deep)...")
            urls = self._run_katana(list(ctx.live_hosts), depth=3)
            all_urls.update(urls)
        
        # Hakrawler
        if check_tool_installed("hakrawler"):
            self.state.current_tool = "hakrawler"
            logger.info("  Running hakrawler...")
            urls = self._run_hakrawler(list(ctx.live_hosts))
            all_urls.update(urls)
        
        ctx.urls = all_urls
        ctx.js_files = {u for u in all_urls if u.endswith('.js') or '.js?' in u}
        
        self._save_list(ctx.data_dir / "urls.txt", ctx.urls)
        
        return ctx
    
    def _stage_js_analysis(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 6: JavaScript Analysis
        Tools: getJS, linkfinder, secretfinder
        """
        if not ctx.js_files and not ctx.live_hosts:
            return ctx
        
        logger.info(f"[Stage 6] JS Analysis")
        self.state.current_module = "js_analysis"
        
        # getJS to find more JS files
        if check_tool_installed("getJS") and ctx.live_hosts:
            self.state.current_tool = "getJS"
            logger.info("  Running getJS...")
            js_files = self._run_getjs(list(ctx.live_hosts)[:20])
            ctx.js_files.update(js_files)
        
        # LinkFinder for endpoints in JS
        if check_tool_installed("linkfinder") and ctx.js_files:
            self.state.current_tool = "linkfinder"
            logger.info(f"  Running linkfinder on {len(ctx.js_files)} JS files...")
            endpoints = self._run_linkfinder(list(ctx.js_files)[:50])
            ctx.endpoints.update(endpoints)
            logger.info(f"  linkfinder: {len(endpoints)} endpoints")
        
        # Save endpoints
        self._save_list(ctx.data_dir / "endpoints.txt", ctx.endpoints)
        self._save_list(ctx.data_dir / "js_files.txt", ctx.js_files)
        
        return ctx
    
    def _stage_content_discovery(self, ctx: ScanContext) -> ScanContext:
        """
        Content Discovery for NARROW mode
        Tools: ffuf, feroxbuster
        """
        if not ctx.live_hosts:
            return ctx
        
        logger.info(f"[Stage] Content Discovery")
        self.state.current_module = "content_discovery"
        
        targets = list(ctx.live_hosts)[:5]  # Limit to avoid long scans
        
        # ffuf
        if check_tool_installed("ffuf"):
            self.state.current_tool = "ffuf"
            for target in targets:
                if not self.running:
                    break
                logger.info(f"  Running ffuf on {target}...")
                self._run_ffuf(target, ctx.data_dir)
        
        return ctx
    
    def _stage_screenshots(self, ctx: ScanContext) -> ScanContext:
        """
        Stage 7: Screenshots
        Tools: gowitness, eyewitness
        """
        if not ctx.live_hosts:
            return ctx
        
        logger.info(f"[Stage 7] Screenshots")
        self.state.current_module = "screenshots"
        
        ss_dir = ctx.data_dir / "screenshots"
        ensure_dir(ss_dir)
        
        # gowitness
        if check_tool_installed("gowitness"):
            self.state.current_tool = "gowitness"
            logger.info(f"  Running gowitness on {len(ctx.live_hosts)} hosts...")
            self._run_gowitness(list(ctx.live_hosts), ss_dir)
        
        # eyewitness as fallback
        elif check_tool_installed("eyewitness"):
            self.state.current_tool = "eyewitness"
            logger.info(f"  Running eyewitness on {len(ctx.live_hosts)} hosts...")
            self._run_eyewitness(list(ctx.live_hosts), ss_dir)
        
        return ctx
    
    def _stage_vuln_scanning(self, ctx: ScanContext, focused: bool = False) -> ScanContext:
        """
        Stage 8: Vulnerability Scanning
        Tools: nuclei
        """
        targets = list(ctx.live_hosts) if ctx.live_hosts else list(ctx.subdomains)
        if not targets:
            return ctx
        
        logger.info(f"[Stage 8] Vulnerability Scanning")
        self.state.current_module = "vulnerability_scanning"
        
        # Nuclei
        if check_tool_installed("nuclei"):
            self.state.current_tool = "nuclei"
            logger.info(f"  Running nuclei on {len(targets)} targets...")
            vulns = self._run_nuclei(targets, ctx.data_dir, focused=focused)
            ctx.vulnerabilities = vulns
            logger.info(f"  nuclei: {len(vulns)} vulnerabilities found")
            
            # Notify critical/high vulns
            for v in vulns:
                if v.get("severity") in ("critical", "high"):
                    try:
                        vuln_obj = Vulnerability(
                            target=v.get("host", ""),
                            name=v.get("name", ""),
                            severity=Severity(v.get("severity", "info")),
                            template_id=v.get("template_id"),
                            description=v.get("description"),
                            discovered_at=get_timestamp()
                        )
                        self.notifier.notify_vulnerability(vuln_obj)
                    except:
                        pass
        
        return ctx
    
    # ==================== TOOL RUNNERS ====================
    
    def _run_subfinder(self, target: str) -> List[str]:
        """Run subfinder"""
        cmd = ["subfinder", "-d", target, "-silent", "-all"]
        code, stdout, stderr = self._cmd(cmd, timeout=600)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_amass(self, target: str) -> List[str]:
        """Run amass passive"""
        cmd = ["amass", "enum", "-passive", "-d", target]
        code, stdout, stderr = self._cmd(cmd, timeout=900)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_assetfinder(self, target: str) -> List[str]:
        """Run assetfinder"""
        cmd = ["assetfinder", "--subs-only", target]
        code, stdout, stderr = self._cmd(cmd, timeout=300)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip() and target in l]
        return []
    
    def _run_findomain(self, target: str) -> List[str]:
        """Run findomain"""
        cmd = ["findomain", "-t", target, "-q"]
        code, stdout, stderr = self._cmd(cmd, timeout=300)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_crtsh(self, target: str) -> List[str]:
        """Query crt.sh"""
        import urllib.request
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            with urllib.request.urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode())
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for s in name.split('\n'):
                        s = s.strip().lower()
                        if s and '*' not in s:
                            subs.add(s)
                return list(subs)
        except:
            return []
    
    def _run_chaos(self, target: str, api_key: str) -> List[str]:
        """Run chaos-client"""
        cmd = ["chaos", "-d", target, "-key", api_key, "-silent"]
        code, stdout, stderr = self._cmd(cmd, timeout=300)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_github_subdomains(self, target: str, token: str) -> List[str]:
        """Run github-subdomains"""
        cmd = ["github-subdomains", "-d", target, "-t", token]
        code, stdout, stderr = self._cmd(cmd, timeout=300)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_dnsx(self, hosts: List[str]) -> Dict[str, List[str]]:
        """Run dnsx for DNS resolution"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            temp_file = f.name
        
        try:
            resolvers = self.config.get("dns_resolution.resolvers", "/opt/security-recon/config/resolvers.txt")
            cmd = ["dnsx", "-l", temp_file, "-a", "-resp", "-json", "-silent"]
            if Path(resolvers).exists():
                cmd.extend(["-r", resolvers])
            
            code, stdout, stderr = self._cmd(cmd, timeout=600)
            
            resolved = {}
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            host = data.get("host", "")
                            ips = data.get("a", [])
                            if host and ips:
                                resolved[host] = ips
                        except:
                            continue
            return resolved
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_naabu(self, hosts: List[str]) -> Dict[str, List[int]]:
        """Run naabu port scanner"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            temp_file = f.name
        
        try:
            cmd = ["naabu", "-l", temp_file, "-json", "-silent", "-top-ports", "1000"]
            code, stdout, stderr = self._cmd(cmd, timeout=1800)
            
            ports = {}
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            host = data.get("host", "")
                            port = data.get("port", 0)
                            if host and port:
                                if host not in ports:
                                    ports[host] = []
                                ports[host].append(port)
                        except:
                            continue
            return ports
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_httpx(self, targets: List[str]) -> tuple:
        """Run httpx with tech detection"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        try:
            cmd = [
                "httpx", "-l", temp_file, "-json", "-silent",
                "-status-code", "-title", "-tech-detect", "-follow-redirects"
            ]
            code, stdout, stderr = self._cmd(cmd, timeout=1800)
            
            live = []
            techs = {}
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            url = data.get("url", "")
                            if url:
                                live.append(url)
                                if data.get("tech"):
                                    techs[url] = data["tech"]
                        except:
                            continue
            return live, techs
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_gau(self, targets: List[str]) -> List[str]:
        """Run gau"""
        all_urls = []
        for target in targets[:10]:  # Limit
            cmd = ["gau", "--subs", target]
            code, stdout, stderr = self._cmd(cmd, timeout=300)
            if code == 0:
                all_urls.extend([l.strip() for l in stdout.split('\n') if l.strip()])
        return all_urls
    
    def _run_waymore(self, target: str) -> List[str]:
        """Run waymore"""
        cmd = ["waymore", "-i", target, "-mode", "U"]
        code, stdout, stderr = self._cmd(cmd, timeout=600)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_waybackurls(self, target: str) -> List[str]:
        """Run waybackurls"""
        cmd = ["waybackurls", target]
        code, stdout, stderr = self._cmd(cmd, timeout=300)
        if code == 0:
            return [l.strip() for l in stdout.split('\n') if l.strip()]
        return []
    
    def _run_katana(self, targets: List[str], depth: int = 2) -> List[str]:
        """Run katana crawler"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        try:
            cmd = ["katana", "-list", temp_file, "-silent", "-d", str(depth), "-jc"]
            code, stdout, stderr = self._cmd(cmd, timeout=900)
            if code == 0:
                return [l.strip() for l in stdout.split('\n') if l.strip()]
            return []
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_hakrawler(self, targets: List[str]) -> List[str]:
        """Run hakrawler"""
        all_urls = []
        for target in targets[:5]:
            cmd = ["hakrawler", "-url", target, "-plain", "-subs"]
            code, stdout, stderr = self._cmd(cmd, timeout=300)
            if code == 0:
                all_urls.extend([l.strip() for l in stdout.split('\n') if l.strip()])
        return all_urls
    
    def _run_getjs(self, targets: List[str]) -> List[str]:
        """Run getJS"""
        all_js = []
        for target in targets:
            cmd = ["getJS", "--url", target, "--complete"]
            code, stdout, stderr = self._cmd(cmd, timeout=120)
            if code == 0:
                all_js.extend([l.strip() for l in stdout.split('\n') if l.strip() and '.js' in l])
        return all_js
    
    def _run_linkfinder(self, js_files: List[str]) -> List[str]:
        """Run linkfinder on JS files"""
        all_endpoints = []
        for js_url in js_files:
            cmd = ["linkfinder", "-i", js_url, "-o", "cli"]
            code, stdout, stderr = self._cmd(cmd, timeout=60)
            if code == 0:
                all_endpoints.extend([l.strip() for l in stdout.split('\n') if l.strip()])
        return all_endpoints
    
    def _run_ffuf(self, target: str, output_dir: Path):
        """Run ffuf"""
        wordlist = self.config.get("content_discovery.wordlist", "/opt/security-recon/wordlists/common.txt")
        if not Path(wordlist).exists():
            return
        
        output_file = output_dir / f"ffuf_{self._sanitize_target(target)}.json"
        cmd = [
            "ffuf", "-u", f"{target}/FUZZ", "-w", wordlist,
            "-o", str(output_file), "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-t", "50", "-s"
        ]
        self._cmd(cmd, timeout=600)
    
    def _run_gowitness(self, targets: List[str], output_dir: Path):
        """Run gowitness"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        try:
            cmd = ["gowitness", "file", "-f", temp_file, "-P", str(output_dir), "--timeout", "10"]
            self._cmd(cmd, timeout=3600)
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_eyewitness(self, targets: List[str], output_dir: Path):
        """Run eyewitness"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        try:
            cmd = ["eyewitness", "-f", temp_file, "-d", str(output_dir), "--no-prompt"]
            self._cmd(cmd, timeout=3600)
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_nuclei(self, targets: List[str], output_dir: Path, focused: bool = False) -> List[Dict]:
        """Run nuclei"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        vulns_dir = output_dir / "vulnerabilities"
        ensure_dir(vulns_dir)
        output_file = vulns_dir / "nuclei.json"
        
        try:
            cmd = ["nuclei", "-l", temp_file, "-o", str(output_file), "-json", "-silent"]
            
            if focused:
                # For narrow mode, use specific templates
                cmd.extend(["-severity", "critical,high,medium"])
            else:
                cmd.extend(["-severity", "critical,high,medium,low"])
            
            # Rate limiting
            cmd.extend(["-rate-limit", "100", "-c", "25"])
            
            self._cmd(cmd, timeout=7200)
            
            vulns = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                vulns.append({
                                    "host": data.get("host", ""),
                                    "name": data.get("info", {}).get("name", ""),
                                    "severity": data.get("info", {}).get("severity", "info"),
                                    "template_id": data.get("template-id", ""),
                                    "description": data.get("info", {}).get("description", ""),
                                    "matcher_name": data.get("matcher-name", ""),
                                    "extracted": data.get("extracted-results", [])
                                })
                            except:
                                continue
            return vulns
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    # ==================== HELPERS ====================
    
    def _save_list(self, filepath: Path, items):
        """Save list to file"""
        with open(filepath, 'w') as f:
            for item in sorted(items):
                f.write(f"{item}\n")
    
    def _save_results(self, ctx: ScanContext):
        """Save all results to files"""
        results = {
            "target": ctx.target,
            "mode": ctx.mode.value,
            "scanned_at": get_timestamp(),
            "stats": {
                "subdomains": len(ctx.subdomains),
                "resolved": len(ctx.resolved_hosts),
                "live_hosts": len(ctx.live_hosts),
                "ports": sum(len(p) for p in ctx.open_ports.values()),
                "urls": len(ctx.urls),
                "js_files": len(ctx.js_files),
                "endpoints": len(ctx.endpoints),
                "vulnerabilities": len(ctx.vulnerabilities)
            },
            "errors": ctx.errors
        }
        
        with open(ctx.data_dir / "scan_summary.json", 'w') as f:
            json.dump(results, f, indent=2)
    
    def stop(self):
        """Stop the scan gracefully"""
        self.running = False
        self.paused = True
        self._save_state()


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Recon Scan Engine")
    parser.add_argument("-t", "--targets", nargs="+", help="Target domains/URLs")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-m", "--mode", choices=["wide", "narrow"], default="wide",
                        help="Scan mode: wide (infrastructure) or narrow (application)")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxychains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    targets = []
    if args.targets:
        targets = args.targets
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not targets and not args.resume:
        parser.error("Must provide targets or use --resume")
    
    mode = ScanMode.WIDE if args.mode == "wide" else ScanMode.NARROW
    
    engine = ScanEngine(use_proxychains=not args.no_proxy)
    stats = engine.run_scan(targets, mode=mode, resume=args.resume)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(json.dumps(stats, indent=2))
    
    def _load_state(self) -> Optional[ScanState]:
        """Load saved scan state"""
        state_file = Path(self.config.get("general.state_file", "/opt/security-recon/state/scan_state.json"))
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
                return ScanState(
                    scan_id=data["scan_id"],
                    targets=data["targets"],
                    current_target_index=data["current_target_index"],
                    current_module=data["current_module"],
                    current_tool=data["current_tool"],
                    completed_modules=data["completed_modules"],
                    status=ScanStatus(data["status"]),
                    started_at=data["started_at"],
                    last_updated=data["last_updated"],
                    error_count=data["error_count"],
                    resume_data=data.get("resume_data", {})
                )
        return None
    
    def run_scan(self, targets: List[str], resume: bool = False) -> Dict[str, Any]:
        """Run a full reconnaissance scan on targets"""
        start_time = datetime.now()
        
        # Check for resume
        if resume:
            saved_state = self._load_state()
            if saved_state and saved_state.status in (ScanStatus.RUNNING, ScanStatus.PAUSED):
                self.state = saved_state
                targets = self.state.targets
                logger.info(f"Resuming scan {self.state.scan_id} from target {self.state.current_target_index}")
            else:
                resume = False
        
        if not resume:
            from shared.utils import generate_scan_id
            self.state = ScanState(
                scan_id=generate_scan_id(targets),
                targets=targets,
                started_at=get_timestamp()
            )
        
        self.running = True
        self.state.status = ScanStatus.RUNNING
        
        # Get enabled modules
        enabled_modules = self._get_enabled_modules()
        
        # Notify scan start
        try:
            self.notifier.notify_scan_start(targets, enabled_modules)
        except Exception as e:
            logger.warning(f"Failed to send start notification: {e}")
        
        try:
            # Process each target
            for i, target in enumerate(targets[self.state.current_target_index:], self.state.current_target_index):
                if not self.running:
                    break
                
                self.state.current_target_index = i
                logger.info(f"Processing target {i+1}/{len(targets)}: {target}")
                
                # Run each module
                for module in enabled_modules:
                    if not self.running:
                        break
                    
                    # Skip if already completed for this target
                    target_completed = self.state.completed_modules.get(target, [])
                    if module in target_completed:
                        logger.info(f"Skipping completed module {module} for {target}")
                        continue
                    
                    self.state.current_module = module
                    self._save_state()
                    
                    try:
                        self._run_module(target, module)
                        
                        # Mark as completed
                        if target not in self.state.completed_modules:
                            self.state.completed_modules[target] = []
                        self.state.completed_modules[target].append(module)
                    except Exception as e:
                        logger.error(f"Error in module {module} for {target}: {e}")
                        self.state.error_count += 1
                        try:
                            self.notifier.notify_error(str(e), f"Module: {module}, Target: {target}")
                        except:
                            pass
            
            # Mark as completed
            if self.running:
                self.state.status = ScanStatus.COMPLETED
            else:
                self.state.status = ScanStatus.PAUSED
        
        except Exception as e:
            self.state.status = ScanStatus.FAILED
            logger.error(f"Scan failed: {e}")
            try:
                self.notifier.notify_error(str(e), "Scan Engine")
            except:
                pass
        
        finally:
            self._save_state()
            self.running = False
        
        # Calculate stats
        duration = datetime.now() - start_time
        stats = {
            "scan_id": self.state.scan_id,
            "status": self.state.status.value,
            "duration": str(duration),
            "targets_processed": self.state.current_target_index + 1,
            "total_targets": len(targets),
            "subdomains": len(self.results["subdomains"]),
            "live_hosts": len([s for s in self.results["subdomains"] if s.get("is_alive")]),
            "ports": len(self.results["ports"]),
            "vulnerabilities": len(self.results["vulnerabilities"]),
            "errors": self.state.error_count
        }
        
        # Notify completion
        try:
            self.notifier.notify_scan_complete(stats)
        except Exception as e:
            logger.warning(f"Failed to send completion notification: {e}")
        
        return stats
    
    def _get_enabled_modules(self) -> List[str]:
        """Get list of enabled modules in execution order"""
        module_order = [
            "subdomain_enumeration",
            "dns_resolution",
            "port_scanning",
            "http_probing",
            "screenshot",
            "content_discovery",
            "javascript_analysis",
            "vulnerability_scanning",
            "cloud_enum",
        ]
        return [m for m in module_order if self.config.is_module_enabled(m)]
    
    def _run_module(self, target: str, module: str):
        """Run a specific scan module"""
        logger.info(f"Running module: {module}")
        
        module_runners = {
            "subdomain_enumeration": self._run_subdomain_enum,
            "dns_resolution": self._run_dns_resolution,
            "port_scanning": self._run_port_scanning,
            "http_probing": self._run_http_probing,
            "screenshot": self._run_screenshot,
            "content_discovery": self._run_content_discovery,
            "javascript_analysis": self._run_js_analysis,
            "vulnerability_scanning": self._run_vuln_scanning,
            "cloud_enum": self._run_cloud_enum,
        }
        
        if module in module_runners:
            module_runners[module](target)
        else:
            logger.warning(f"Unknown module: {module}")
    
    def _run_subdomain_enum(self, target: str):
        """Run subdomain enumeration tools"""
        all_subdomains = set()
        
        # Subfinder
        if self._is_tool_enabled("subdomain_enumeration", "subfinder"):
            subs = self._run_subfinder(target)
            all_subdomains.update(subs)
        
        # Amass
        if self._is_tool_enabled("subdomain_enumeration", "amass"):
            subs = self._run_amass(target)
            all_subdomains.update(subs)
        
        # Assetfinder
        if self._is_tool_enabled("subdomain_enumeration", "assetfinder"):
            subs = self._run_assetfinder(target)
            all_subdomains.update(subs)
        
        # Findomain
        if self._is_tool_enabled("subdomain_enumeration", "findomain"):
            subs = self._run_findomain(target)
            all_subdomains.update(subs)
        
        # crt.sh
        if self._is_tool_enabled("subdomain_enumeration", "crt_sh"):
            subs = self._run_crtsh(target)
            all_subdomains.update(subs)
        
        # Deduplicate and store
        unique_subs = deduplicate_subdomains(list(all_subdomains))
        logger.info(f"Found {len(unique_subs)} unique subdomains for {target}")
        
        # Store results
        for sub in unique_subs:
            self.results["subdomains"].append({
                "subdomain": sub,
                "domain": target,
                "discovered_at": get_timestamp()
            })
        
        # Save to file
        output_file = self.data_dir / target / "subdomains.txt"
        ensure_dir(output_file.parent)
        with open(output_file, 'w') as f:
            f.write('\n'.join(unique_subs))
        
        # Notify new subdomains
        if unique_subs:
            try:
                self.notifier.notify_new_subdomains(target, unique_subs[:50])  # Limit to 50
            except:
                pass
    
    def _run_subfinder(self, target: str) -> List[str]:
        """Run subfinder"""
        config = self._get_tool_config("subdomain_enumeration", "subfinder")
        cmd = ["subfinder", "-d", target, "-silent"]
        
        if config.get("threads"):
            cmd.extend(["-t", str(config["threads"])])
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=config.get("timeout", 300),
            use_proxychains=self._use_proxychains()
        )
        
        if code == 0:
            return [line.strip() for line in stdout.split('\n') if line.strip()]
        else:
            logger.error(f"Subfinder error: {stderr}")
            return []
    
    def _run_amass(self, target: str) -> List[str]:
        """Run amass"""
        config = self._get_tool_config("subdomain_enumeration", "amass")
        cmd = ["amass", "enum", "-d", target]
        
        if config.get("passive_only"):
            cmd.append("-passive")
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=config.get("timeout", 600),
            use_proxychains=self._use_proxychains()
        )
        
        if code == 0:
            return [line.strip() for line in stdout.split('\n') if line.strip()]
        else:
            logger.error(f"Amass error: {stderr}")
            return []
    
    def _run_assetfinder(self, target: str) -> List[str]:
        """Run assetfinder"""
        config = self._get_tool_config("subdomain_enumeration", "assetfinder")
        cmd = ["assetfinder"]
        
        if config.get("subs_only"):
            cmd.append("--subs-only")
        
        cmd.append(target)
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=300,
            use_proxychains=self._use_proxychains()
        )
        
        if code == 0:
            return [line.strip() for line in stdout.split('\n') if line.strip() and target in line]
        else:
            logger.error(f"Assetfinder error: {stderr}")
            return []
    
    def _run_findomain(self, target: str) -> List[str]:
        """Run findomain"""
        config = self._get_tool_config("subdomain_enumeration", "findomain")
        cmd = ["findomain", "-t", target, "-q"]
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=300,
            use_proxychains=self._use_proxychains()
        )
        
        if code == 0:
            return [line.strip() for line in stdout.split('\n') if line.strip()]
        else:
            logger.error(f"Findomain error: {stderr}")
            return []
    
    def _run_crtsh(self, target: str) -> List[str]:
        """Query crt.sh for certificate transparency logs"""
        import urllib.request
        import urllib.error
        
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            with urllib.request.urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode())
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub:
                            subdomains.add(sub)
                return list(subdomains)
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
            return []
    
    def _run_dns_resolution(self, target: str):
        """Run DNS resolution on discovered subdomains"""
        # Get subdomains from file
        subs_file = self.data_dir / target / "subdomains.txt"
        if not subs_file.exists():
            logger.warning(f"No subdomains file for {target}")
            return
        
        with open(subs_file) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        if not subdomains:
            return
        
        # Run dnsx
        if self._is_tool_enabled("dns_resolution", "dnsx"):
            resolved = self._run_dnsx(subdomains)
            
            # Update subdomains with resolved IPs
            for sub, ips in resolved.items():
                for result in self.results["subdomains"]:
                    if result["subdomain"] == sub:
                        result["ip_addresses"] = ips
                        result["is_alive"] = len(ips) > 0
            
            # Save resolved
            output_file = self.data_dir / target / "resolved.txt"
            with open(output_file, 'w') as f:
                for sub, ips in resolved.items():
                    f.write(f"{sub}: {', '.join(ips)}\n")
    
    def _run_dnsx(self, subdomains: List[str]) -> Dict[str, List[str]]:
        """Run dnsx for DNS resolution"""
        config = self._get_tool_config("dns_resolution", "dnsx")
        
        # Write subdomains to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            temp_file = f.name
        
        try:
            cmd = ["dnsx", "-l", temp_file, "-a", "-resp", "-json", "-silent"]
            
            if config.get("threads"):
                cmd.extend(["-t", str(config["threads"])])
            
            resolvers = config.get("resolvers")
            if resolvers and Path(resolvers).exists():
                cmd.extend(["-r", resolvers])
            
            code, stdout, stderr = run_command(cmd, timeout=600)
            
            resolved = {}
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            host = data.get("host", "")
                            ips = data.get("a", [])
                            if host and ips:
                                resolved[host] = ips
                        except json.JSONDecodeError:
                            continue
            
            return resolved
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_port_scanning(self, target: str):
        """Run port scanning"""
        # Get live hosts
        subs_file = self.data_dir / target / "subdomains.txt"
        if not subs_file.exists():
            return
        
        with open(subs_file) as f:
            hosts = [line.strip() for line in f if line.strip()]
        
        # Naabu
        if self._is_tool_enabled("port_scanning", "naabu"):
            ports = self._run_naabu(hosts)
            self.results["ports"].extend(ports)
            
            # Save ports
            output_file = self.data_dir / target / "ports.txt"
            with open(output_file, 'w') as f:
                for p in ports:
                    f.write(f"{p['host']}:{p['port']}\n")
    
    def _run_naabu(self, hosts: List[str]) -> List[Dict]:
        """Run naabu port scanner"""
        config = self._get_tool_config("port_scanning", "naabu")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            temp_file = f.name
        
        try:
            cmd = ["naabu", "-l", temp_file, "-json", "-silent"]
            
            if config.get("rate"):
                cmd.extend(["-rate", str(config["rate"])])
            if config.get("ports"):
                cmd.extend(["-p", config["ports"]])
            
            code, stdout, stderr = run_command(
                cmd,
                timeout=1800,
                use_proxychains=self._use_proxychains()
            )
            
            ports = []
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            ports.append({
                                "host": data.get("host", ""),
                                "port": data.get("port", 0),
                                "protocol": "tcp",
                                "discovered_at": get_timestamp()
                            })
                        except json.JSONDecodeError:
                            continue
            
            return ports
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_http_probing(self, target: str):
        """Run HTTP probing"""
        subs_file = self.data_dir / target / "subdomains.txt"
        if not subs_file.exists():
            return
        
        with open(subs_file) as f:
            hosts = [line.strip() for line in f if line.strip()]
        
        if self._is_tool_enabled("http_probing", "httpx"):
            endpoints = self._run_httpx(hosts)
            self.results["http_endpoints"].extend(endpoints)
            
            # Save live hosts
            output_file = self.data_dir / target / "live_hosts.txt"
            with open(output_file, 'w') as f:
                for ep in endpoints:
                    f.write(f"{ep['url']}\n")
    
    def _run_httpx(self, hosts: List[str]) -> List[Dict]:
        """Run httpx HTTP prober"""
        config = self._get_tool_config("http_probing", "httpx")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            temp_file = f.name
        
        try:
            cmd = ["httpx", "-l", temp_file, "-json", "-silent"]
            
            if config.get("threads"):
                cmd.extend(["-threads", str(config["threads"])])
            if config.get("follow_redirects"):
                cmd.append("-follow-redirects")
            if config.get("status_codes"):
                cmd.append("-status-code")
            if config.get("title"):
                cmd.append("-title")
            if config.get("tech_detect"):
                cmd.append("-tech-detect")
            
            code, stdout, stderr = run_command(
                cmd,
                timeout=1800,
                use_proxychains=self._use_proxychains()
            )
            
            endpoints = []
            if code == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            endpoints.append({
                                "url": data.get("url", ""),
                                "status_code": data.get("status_code", 0),
                                "title": data.get("title", ""),
                                "technologies": data.get("tech", []),
                                "content_length": data.get("content_length", 0),
                                "server": data.get("webserver", ""),
                                "discovered_at": get_timestamp()
                            })
                        except json.JSONDecodeError:
                            continue
            
            return endpoints
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    def _run_screenshot(self, target: str):
        """Take screenshots of live hosts"""
        live_file = self.data_dir / target / "live_hosts.txt"
        if not live_file.exists():
            return
        
        if self._is_tool_enabled("screenshot", "gowitness"):
            self._run_gowitness(target, live_file)
    
    def _run_gowitness(self, target: str, urls_file: Path):
        """Run gowitness"""
        config = self._get_tool_config("screenshot", "gowitness")
        output_dir = self.data_dir / target / "screenshots"
        ensure_dir(output_dir)
        
        cmd = [
            "gowitness", "file", "-f", str(urls_file),
            "-P", str(output_dir),
            "--timeout", str(config.get("timeout", 10))
        ]
        
        if config.get("threads"):
            cmd.extend(["-t", str(config["threads"])])
        
        code, stdout, stderr = run_command(cmd, timeout=3600)
        if code != 0:
            logger.error(f"Gowitness error: {stderr}")
    
    def _run_content_discovery(self, target: str):
        """Run content discovery/directory bruteforcing"""
        live_file = self.data_dir / target / "live_hosts.txt"
        if not live_file.exists():
            return
        
        with open(live_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        # Limit URLs to avoid long scans
        urls = urls[:20]
        
        if self._is_tool_enabled("content_discovery", "ffuf"):
            for url in urls:
                if not self.running:
                    break
                self._run_ffuf(target, url)
    
    def _run_ffuf(self, target: str, url: str):
        """Run ffuf"""
        config = self._get_tool_config("content_discovery", "ffuf")
        wordlist = config.get("wordlist", "/opt/security-recon/wordlists/common.txt")
        
        if not Path(wordlist).exists():
            logger.warning(f"Wordlist not found: {wordlist}")
            return
        
        # Create output directory
        from shared.utils import sanitize_filename
        output_dir = self.data_dir / target / "content_discovery"
        ensure_dir(output_dir)
        output_file = output_dir / f"{sanitize_filename(url)}.json"
        
        cmd = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
            "-o", str(output_file), "-of", "json",
            "-mc", "200,201,202,203,204,301,302,307,401,403",
            "-s"
        ]
        
        if config.get("threads"):
            cmd.extend(["-t", str(config["threads"])])
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=config.get("timeout", 600),
            use_proxychains=self._use_proxychains()
        )
        
        if code != 0:
            logger.warning(f"ffuf error for {url}: {stderr}")
    
    def _run_js_analysis(self, target: str):
        """Run JavaScript analysis"""
        live_file = self.data_dir / target / "live_hosts.txt"
        if not live_file.exists():
            return
        
        # This would run tools like getJS, linkfinder, secretfinder
        # Simplified implementation
        pass
    
    def _run_vuln_scanning(self, target: str):
        """Run vulnerability scanning"""
        live_file = self.data_dir / target / "live_hosts.txt"
        if not live_file.exists():
            return
        
        if self._is_tool_enabled("vulnerability_scanning", "nuclei"):
            vulns = self._run_nuclei(target, live_file)
            self.results["vulnerabilities"].extend(vulns)
            
            # Notify for critical/high vulns
            for v in vulns:
                if v.get("severity") in ("critical", "high"):
                    try:
                        vuln_obj = Vulnerability(
                            target=v["target"],
                            name=v["name"],
                            severity=Severity(v["severity"]),
                            template_id=v.get("template_id"),
                            description=v.get("description"),
                            discovered_at=v["discovered_at"]
                        )
                        self.notifier.notify_vulnerability(vuln_obj)
                    except:
                        pass
    
    def _run_nuclei(self, target: str, urls_file: Path) -> List[Dict]:
        """Run nuclei vulnerability scanner"""
        config = self._get_tool_config("vulnerability_scanning", "nuclei")
        output_dir = self.data_dir / target / "vulnerabilities"
        ensure_dir(output_dir)
        output_file = output_dir / "nuclei.json"
        
        cmd = [
            "nuclei", "-l", str(urls_file),
            "-o", str(output_file), "-json",
            "-silent"
        ]
        
        if config.get("templates"):
            cmd.extend(["-t", config["templates"]])
        if config.get("severity"):
            cmd.extend(["-severity", config["severity"]])
        if config.get("rate_limit"):
            cmd.extend(["-rate-limit", str(config["rate_limit"])])
        if config.get("concurrency"):
            cmd.extend(["-c", str(config["concurrency"])])
        
        code, stdout, stderr = run_command(
            cmd,
            timeout=7200,  # 2 hours
            use_proxychains=self._use_proxychains()
        )
        
        vulns = []
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            vulns.append({
                                "target": data.get("host", ""),
                                "name": data.get("info", {}).get("name", ""),
                                "severity": data.get("info", {}).get("severity", "info"),
                                "template_id": data.get("template-id", ""),
                                "description": data.get("info", {}).get("description", ""),
                                "matcher_name": data.get("matcher-name", ""),
                                "extracted_results": data.get("extracted-results", []),
                                "discovered_at": get_timestamp()
                            })
                        except json.JSONDecodeError:
                            continue
        
        return vulns
    
    def _run_cloud_enum(self, target: str):
        """Run cloud enumeration"""
        # Simplified - would run cloud_enum, S3Scanner, etc.
        pass
    
    def stop(self):
        """Stop the scan gracefully"""
        self.running = False
        self.paused = True
        self._save_state()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Recon Scan Engine")
    parser.add_argument("-t", "--targets", nargs="+", help="Target domains")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    targets = []
    if args.targets:
        targets = args.targets
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    
    if not targets and not args.resume:
        parser.error("Must provide targets or use --resume")
    
    engine = ScanEngine()
    stats = engine.run_scan(targets, resume=args.resume)
    print(json.dumps(stats, indent=2))
