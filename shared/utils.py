"""
Utility functions for Security Recon Platform
"""
import json
import hashlib
import subprocess
import shutil
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


def get_timestamp() -> str:
    """Get current ISO timestamp"""
    return datetime.utcnow().isoformat() + "Z"


def generate_scan_id(targets: List[str]) -> str:
    """Generate unique scan ID based on targets and timestamp"""
    content = f"{','.join(sorted(targets))}:{get_timestamp()}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def ensure_dir(path: Path) -> Path:
    """Ensure directory exists"""
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def is_in_scope(target: str, scope_patterns: List[str], exclude_patterns: List[str] = None) -> bool:
    """Check if target is in scope"""
    exclude_patterns = exclude_patterns or []
    
    # Check exclusions first
    for pattern in exclude_patterns:
        if re.match(pattern, target):
            return False
    
    # If no scope patterns, everything not excluded is in scope
    if not scope_patterns:
        return True
    
    # Check if matches any scope pattern
    for pattern in scope_patterns:
        if re.match(pattern, target):
            return True
    
    return False


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    url = re.sub(r'^https?://', '', url)
    url = url.split('/')[0]
    url = url.split(':')[0]
    return url


def merge_results(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Merge scan results, preserving existing data and adding new"""
    merged = existing.copy()
    
    for key, value in new.items():
        if key not in merged:
            merged[key] = value
        elif isinstance(value, list) and isinstance(merged[key], list):
            # Merge lists, avoiding duplicates
            existing_set = set(str(item) for item in merged[key])
            for item in value:
                if str(item) not in existing_set:
                    merged[key].append(item)
        elif isinstance(value, dict) and isinstance(merged[key], dict):
            merged[key] = merge_results(merged[key], value)
        else:
            merged[key] = value
    
    return merged


def deduplicate_subdomains(subdomains: List[str]) -> List[str]:
    """Remove duplicate subdomains, case-insensitive"""
    seen = set()
    result = []
    for sub in subdomains:
        lower = sub.lower().strip()
        if lower and lower not in seen:
            seen.add(lower)
            result.append(lower)
    return sorted(result)


def check_tool_installed(tool: str) -> bool:
    """Check if a tool is installed and available"""
    return shutil.which(tool) is not None


def get_installed_tools() -> Dict[str, bool]:
    """Get installation status of all recon tools"""
    tools = [
        "subfinder", "amass", "assetfinder", "findomain", "httpx", "httprobe",
        "dnsx", "massdns", "naabu", "masscan", "nmap", "ffuf", "feroxbuster",
        "dirsearch", "nuclei", "nikto", "gowitness", "eyewitness", "gau",
        "waybackurls", "hakrawler", "katana", "getJS", "linkfinder"
    ]
    return {tool: check_tool_installed(tool) for tool in tools}


def run_command(
    command: List[str],
    timeout: int = 300,
    use_proxychains: bool = False,
    capture_output: bool = True
) -> Tuple[int, str, str]:
    """Run a command with optional proxychains"""
    if use_proxychains and check_tool_installed("proxychains4"):
        command = ["proxychains4", "-q"] + command
    
    try:
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def parse_ndjson(content: str) -> List[Dict[str, Any]]:
    """Parse newline-delimited JSON"""
    results = []
    for line in content.strip().split('\n'):
        if line.strip():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename"""
    return re.sub(r'[^\w\-.]', '_', name)


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = seconds / 60
        return f"{mins:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def get_file_hash(filepath: Path) -> str:
    """Get SHA256 hash of file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


class RateLimiter:
    """Simple rate limiter"""
    
    def __init__(self, requests_per_second: float):
        self.min_interval = 1.0 / requests_per_second
        self.last_request = 0.0
    
    def wait(self):
        """Wait until rate limit allows next request"""
        import time
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()


class ProgressTracker:
    """Track progress of long-running operations"""
    
    def __init__(self, total: int, description: str = ""):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()
    
    def update(self, n: int = 1):
        self.current += n
    
    def get_progress(self) -> Dict[str, Any]:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        
        return {
            "description": self.description,
            "current": self.current,
            "total": self.total,
            "percentage": (self.current / self.total * 100) if self.total > 0 else 0,
            "elapsed": format_duration(elapsed),
            "eta": format_duration(eta),
            "rate": f"{rate:.1f}/s"
        }
