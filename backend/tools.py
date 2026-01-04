import shutil
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path


def is_tool_installed(tool: str) -> bool:
    """Check if a tool is available in PATH"""
    return shutil.which(tool) is not None


def get_installed_tools() -> Dict[str, bool]:
    """Get installation status of all tools"""
    return {tool: is_tool_installed(tool) for tool in RECON_TOOLS.keys()}


def run_tool(
    tool_name: str,
    target: str,
    output_path: str,
    use_proxychains: bool = True,
    timeout: int = None
) -> Dict[str, Any]:
    """
    Run a recon tool with optional proxychains support
    
    Args:
        tool_name: Name of the tool from RECON_TOOLS
        target: Target domain/URL
        output_path: Path for output file
        use_proxychains: Whether to use proxychains
        timeout: Override default timeout
    
    Returns:
        Dict with status, output, and errors
    """
    if tool_name not in RECON_TOOLS:
        return {"status": "error", "error": f"Unknown tool: {tool_name}"}
    
    tool_config = RECON_TOOLS[tool_name]
    
    if not is_tool_installed(tool_name):
        return {"status": "error", "error": f"Tool not installed: {tool_name}"}
    
    # Build command
    cmd_template = tool_config["command"]
    cmd = cmd_template.format(target=target, output=output_path)
    
    # Prepend proxychains if enabled and available
    if use_proxychains and is_tool_installed("proxychains4"):
        cmd = f"proxychains4 -q {cmd}"
    
    tool_timeout = timeout or tool_config.get("timeout", 600)
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            timeout=tool_timeout,
            capture_output=True,
            text=True
        )
        
        return {
            "status": "success" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_file": output_path
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"Tool timed out after {tool_timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def get_tools_by_category(category: str) -> List[str]:
    """Get all tools in a category"""
    return TOOL_CATEGORIES.get(category, [])


def get_enabled_tools(categories: List[str] = None, tools_config: Dict = None) -> List[str]:
    """Get list of enabled and installed tools"""
    tools_config = tools_config or {}
    enabled = []
    
    for tool_name, tool_info in RECON_TOOLS.items():
        # Skip if category filter and not in category
        if categories and tool_info.get("category") not in categories:
            continue
        
        # Check if explicitly disabled in config
        if tools_config.get(tool_name, {}).get("enabled") == False:
            continue
        
        # Check if installed
        if is_tool_installed(tool_name):
            enabled.append(tool_name)
    
    return enabled


RECON_TOOLS = {
    # ============ SUBDOMAIN ENUMERATION ============
    "subfinder": {
        "command": "subfinder -d {target} -o {output} -all -silent",
        "parser": "line",
        "timeout": 600,
        "category": "subdomain_enumeration",
        "description": "Fast passive subdomain enumeration"
    },
    "amass": {
        "command": "amass enum -d {target} -o {output} -passive",
        "parser": "line",
        "timeout": 1800,
        "category": "subdomain_enumeration",
        "description": "In-depth subdomain enumeration"
    },
    "assetfinder": {
        "command": "assetfinder --subs-only {target} > {output}",
        "parser": "line",
        "timeout": 300,
        "category": "subdomain_enumeration",
        "description": "Find related domains and subdomains"
    },
    "findomain": {
        "command": "findomain -t {target} -u {output}",
        "parser": "line",
        "timeout": 600,
        "category": "subdomain_enumeration",
        "description": "Fast subdomain finder"
    },
    "chaos": {
        "command": "chaos -d {target} -o {output} -silent",
        "parser": "line",
        "timeout": 300,
        "category": "subdomain_enumeration",
        "description": "ProjectDiscovery Chaos client"
    },
    "github-subdomains": {
        "command": "github-subdomains -d {target} -o {output}",
        "parser": "line",
        "timeout": 600,
        "category": "subdomain_enumeration",
        "description": "Find subdomains from GitHub"
    },
    "crt.sh": {
        "command": "curl -s 'https://crt.sh/?q=%25.{target}&output=json' | jq -r '.[].name_value' | sort -u > {output}",
        "parser": "line",
        "timeout": 60,
        "category": "subdomain_enumeration",
        "description": "Certificate transparency logs"
    },
    
    # ============ DNS RESOLUTION ============
    "dnsx": {
        "command": "dnsx -l {input} -resp -a -aaaa -cname -o {output} -silent",
        "parser": "line",
        "timeout": 600,
        "category": "dns_resolution",
        "description": "Fast DNS toolkit"
    },
    "massdns": {
        "command": "massdns -r resolvers.txt -t A -o S -w {output} {input}",
        "parser": "line",
        "timeout": 900,
        "category": "dns_resolution",
        "description": "High-performance DNS resolver"
    },
    
    # ============ PORT SCANNING ============
    "naabu": {
        "command": "naabu -l {input} -o {output} -silent -top-ports 1000",
        "parser": "line",
        "timeout": 1800,
        "category": "port_scanning",
        "description": "Fast port scanner"
    },
    "masscan": {
        "command": "masscan -iL {input} -p1-65535 --rate=1000 -oL {output}",
        "parser": "line",
        "timeout": 3600,
        "category": "port_scanning",
        "description": "Internet-scale port scanner"
    },
    "nmap": {
        "command": "nmap -iL {input} -T4 -sV -oN {output}",
        "parser": "line",
        "timeout": 7200,
        "category": "port_scanning",
        "description": "Network mapper with service detection"
    },
    
    # ============ HTTP PROBING ============
    "httpx": {
        "command": "httpx -l {input} -o {output} -silent -status-code -title -tech-detect -follow-redirects",
        "parser": "json",
        "timeout": 1800,
        "category": "http_probing",
        "description": "HTTP toolkit with tech detection"
    },
    "httprobe": {
        "command": "cat {input} | httprobe > {output}",
        "parser": "line",
        "timeout": 900,
        "category": "http_probing",
        "description": "Probe for HTTP/HTTPS servers"
    },
    
    # ============ URL DISCOVERY ============
    "gau": {
        "command": "gau --subs {target} > {output}",
        "parser": "line",
        "timeout": 600,
        "category": "url_discovery",
        "description": "GetAllUrls from archives"
    },
    "waymore": {
        "command": "waymore -i {target} -mode U -oU {output}",
        "parser": "line",
        "timeout": 900,
        "category": "url_discovery",
        "description": "Find way more URLs"
    },
    "waybackurls": {
        "command": "waybackurls {target} > {output}",
        "parser": "line",
        "timeout": 600,
        "category": "url_discovery",
        "description": "Fetch URLs from Wayback Machine"
    },
    "katana": {
        "command": "katana -u {target} -o {output} -silent -jc -d 3",
        "parser": "line",
        "timeout": 1800,
        "category": "url_discovery",
        "description": "Next-gen crawler"
    },
    "hakrawler": {
        "command": "echo {target} | hakrawler -subs -plain > {output}",
        "parser": "line",
        "timeout": 600,
        "category": "url_discovery",
        "description": "Simple crawler for endpoints"
    },
    "gospider": {
        "command": "gospider -s {target} -o {output} -c 10 -d 3",
        "parser": "line",
        "timeout": 900,
        "category": "url_discovery",
        "description": "Fast web spider"
    },
    "urlfinder": {
        "command": "urlfinder -d {target} -o {output}",
        "parser": "line",
        "timeout": 600,
        "category": "url_discovery",
        "description": "Find URLs in responses"
    },
    
    # ============ JS ANALYSIS ============
    "getJS": {
        "command": "getJS --url {target} --complete > {output}",
        "parser": "line",
        "timeout": 300,
        "category": "js_analysis",
        "description": "Extract JavaScript files"
    },
    "linkfinder": {
        "command": "linkfinder -i {target} -o cli > {output}",
        "parser": "line",
        "timeout": 120,
        "category": "js_analysis",
        "description": "Find endpoints in JS files"
    },
    "secretfinder": {
        "command": "secretfinder -i {target} -o cli > {output}",
        "parser": "line",
        "timeout": 120,
        "category": "js_analysis",
        "description": "Find secrets in JS files"
    },
    "xnLinkFinder": {
        "command": "xnLinkFinder -i {target} -o {output}",
        "parser": "line",
        "timeout": 600,
        "category": "js_analysis",
        "description": "Find links and parameters"
    },
    
    # ============ CONTENT DISCOVERY ============
    "ffuf": {
        "command": "ffuf -u {target}/FUZZ -w wordlist.txt -o {output} -of json -mc 200,201,204,301,302,307,401,403 -s",
        "parser": "json",
        "timeout": 1800,
        "category": "content_discovery",
        "description": "Fast web fuzzer"
    },
    "feroxbuster": {
        "command": "feroxbuster -u {target} -o {output} -q",
        "parser": "line",
        "timeout": 3600,
        "category": "content_discovery",
        "description": "Recursive content discovery"
    },
    "dirsearch": {
        "command": "dirsearch -u {target} -o {output}",
        "parser": "line",
        "timeout": 1800,
        "category": "content_discovery",
        "description": "Web path scanner"
    },
    "gobuster": {
        "command": "gobuster dir -u {target} -w wordlist.txt -o {output}",
        "parser": "line",
        "timeout": 1800,
        "category": "content_discovery",
        "description": "Directory/file brute-forcer"
    },
    
    # ============ VULNERABILITY SCANNING ============
    "nuclei": {
        "command": "nuclei -l {input} -o {output} -silent -severity critical,high,medium",
        "parser": "json",
        "timeout": 7200,
        "category": "vulnerability_scanning",
        "description": "Template-based vulnerability scanner"
    },
    "nikto": {
        "command": "nikto -h {target} -o {output}",
        "parser": "line",
        "timeout": 3600,
        "category": "vulnerability_scanning",
        "description": "Web server scanner"
    },
    
    # ============ SCREENSHOTS ============
    "gowitness": {
        "command": "gowitness file -f {input} -P {output}",
        "parser": "line",
        "timeout": 3600,
        "category": "screenshot",
        "description": "Website screenshot tool"
    },
    "eyewitness": {
        "command": "eyewitness -f {input} -d {output} --no-prompt",
        "parser": "line",
        "timeout": 3600,
        "category": "screenshot",
        "description": "Web screenshot and reporting"
    },
    "aquatone": {
        "command": "cat {input} | aquatone -out {output}",
        "parser": "line",
        "timeout": 1800,
        "category": "screenshot",
        "description": "Visual inspection of websites"
    },
    
    # ============ PROXY ============
    "proxify": {
        "command": "proxify -l {input}",
        "parser": "line",
        "timeout": 0,
        "category": "proxy",
        "description": "Swiss army knife proxy for traffic capture"
    },
    
    # ============ OSINT ============
    "theHarvester": {
        "command": "theHarvester -d {target} -b all -f {output}",
        "parser": "line",
        "timeout": 900,
        "category": "osint",
        "description": "Gather emails, names, subdomains"
    },
    "shodan": {
        "command": "shodan search hostname:{target} > {output}",
        "parser": "line",
        "timeout": 300,
        "category": "osint",
        "description": "Search Shodan"
    },
    
    # ============ CLOUD ============
    "cloud_enum": {
        "command": "cloud_enum -k {target} -l {output}",
        "parser": "line",
        "timeout": 900,
        "category": "cloud",
        "description": "Multi-cloud enumeration"
    },
    "s3scanner": {
        "command": "s3scanner scan -f {input} -o {output}",
        "parser": "json",
        "timeout": 600,
        "category": "cloud",
        "description": "S3 bucket scanner"
    }
}

TOOL_CATEGORIES = {
    "subdomain_enumeration": ["subfinder", "amass", "assetfinder", "findomain", "chaos", "github-subdomains", "crt.sh"],
    "dns_resolution": ["dnsx", "massdns"],
    "port_scanning": ["naabu", "masscan", "nmap"],
    "http_probing": ["httpx", "httprobe"],
    "url_discovery": ["gau", "waymore", "waybackurls", "katana", "hakrawler", "gospider", "urlfinder"],
    "js_analysis": ["getJS", "linkfinder", "secretfinder", "xnLinkFinder"],
    "content_discovery": ["ffuf", "feroxbuster", "dirsearch", "gobuster"],
    "vulnerability_scanning": ["nuclei", "nikto"],
    "screenshot": ["gowitness", "eyewitness", "aquatone"],
    "proxy": ["proxify"],
    "osint": ["theHarvester", "shodan"],
    "cloud": ["cloud_enum", "s3scanner"]
}
