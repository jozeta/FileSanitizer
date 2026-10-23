"""
Subfinder & dnsx Subdomain Enumeration and DNS Resolution Pipeline.
Executes: subfinder -silent -d <domain> | dnsx -silent -a -resp
Parses discovered subdomains and resolved IP addresses.
"""

import shutil
import subprocess
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from app.core.logging_config import logger


class SubfinderDnsxScanner:
    """
    Subdomain reconnaissance pipeline using ProjectDiscovery's Subfinder and dnsx.
    Executes the exact shell pipe:
      subfinder -silent -d <domain> | dnsx -silent -a -resp
    and parses each discovered subdomain with its resolved A-record IP addresses.
    """

    @classmethod
    def _find_binary(cls, name: str) -> Optional[str]:
        """Locates binary in system PATH or standard binary directories."""
        # 1. Standard PATH resolution
        path = shutil.which(name)
        if path:
            return path

        # 2. Common installation prefixes across macOS and Linux containers
        fallbacks = [
            f"/opt/homebrew/bin/{name}",
            f"/usr/local/bin/{name}",
            f"/usr/bin/{name}",
            f"/bin/{name}",
            f"/home/appuser/go/bin/{name}",
            f"/root/go/bin/{name}",
        ]
        for fb in fallbacks:
            if shutil.which(fb):
                return fb

        return None

    @classmethod
    def is_available(cls) -> bool:
        """Returns True if both subfinder and dnsx executables are accessible."""
        return bool(cls._find_binary("subfinder") and cls._find_binary("dnsx"))

    @classmethod
    def get_binary_paths(cls) -> Dict[str, Optional[str]]:
        """Returns the resolved paths of subfinder and dnsx."""
        return {
            "subfinder": cls._find_binary("subfinder"),
            "dnsx": cls._find_binary("dnsx")
        }

    @classmethod
    def clean_domain_target(cls, target: str) -> Optional[str]:
        """
        Extracts, validates, and normalizes a domain target from a domain name or URL.
        Rejects raw IP addresses, invalid characters, and potential command injections.
        """
        if not target or not isinstance(target, str):
            return None

        clean = target.strip().lower()

        # If input is a URL, parse out the hostname
        if "://" in clean or clean.startswith("//") or "/" in clean:
            try:
                if clean.startswith("//"):
                    clean = "https:" + clean
                elif not clean.startswith(("http://", "https://")):
                    clean = "https://" + clean
                parsed = urllib.parse.urlparse(clean)
                clean = parsed.hostname or clean
            except Exception:
                clean = clean.split("/")[0]

        # Strip user credentials, port numbers, trailing colons, dots, and slashes
        clean = clean.split("@")[-1].split(":")[0].strip().rstrip(".")

        # Reject empty or localhost
        if not clean or clean == "localhost":
            return None

        # Reject raw IPv4 address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean):
            return None

        # Reject raw IPv6 address
        if ":" in clean:
            return None

        # Validate standard RFC hostname syntax (only alphanumeric, dashes, dots)
        if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', clean):
            return None

        # Limit maximum domain length
        if len(clean) > 253:
            return None

        return clean

    @classmethod
    def parse_output(cls, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parses output from:
          subfinder -silent -d <domain> | dnsx -silent -a -resp
        Expected output format:
          <subdomain> [A] [<ip>]
        or lines with multiple IPs, stripped of ANSI color codes.
        Returns a deduplicated list of subdomains and resolved IPs.
        """
        if not raw_output:
            return []

        # Strip any ANSI escape color codes
        clean_text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', raw_output)

        line_pattern = re.compile(r"^([a-zA-Z0-9_.-]+)\s+(?:\[[A-Z]+\]\s+)?\[([0-9a-fA-F.:,\s]+)\]")
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        subdomain_ips: Dict[str, Set[str]] = {}

        for line in clean_text.splitlines():
            line = line.strip()
            if not line:
                continue

            m = line_pattern.match(line)
            if m:
                sub = m.group(1).lower().rstrip(".")
                ips = ip_pattern.findall(m.group(2))
                if sub not in subdomain_ips:
                    subdomain_ips[sub] = set()
                subdomain_ips[sub].update(ips)
            else:
                # Fallback check if the line contains a domain followed by an IP
                parts = line.split()
                if len(parts) >= 2:
                    potential_domain = parts[0].lower().rstrip(".")
                    found_ips = ip_pattern.findall(line)
                    if re.match(r'^(?:[a-zA-Z0-9_.-]+\.)+[a-zA-Z]{2,}$', potential_domain) and found_ips:
                        if potential_domain not in subdomain_ips:
                            subdomain_ips[potential_domain] = set()
                        subdomain_ips[potential_domain].update(found_ips)
                elif re.match(r'^(?:[a-zA-Z0-9_.-]+\.)+[a-zA-Z]{2,}$', line):
                    sub = line.lower().rstrip(".")
                    if sub not in subdomain_ips:
                        subdomain_ips[sub] = set()

        results: List[Dict[str, Any]] = []
        for sub in sorted(subdomain_ips.keys()):
            ips = sorted(list(subdomain_ips[sub]))
            results.append({
                "subdomain": sub,
                "domain": sub,
                "ips": ips,
                "status": "active" if ips else "unresolving",
                "status_label": "Active (Resolving)" if ips else "Unresolved (Dormant)",
                "discovered_from": "Subfinder + dnsx",
                "sources": ["Subfinder", "dnsx"]
            })

        return results

    @classmethod
    def discover_subdomains(cls, target: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Executes:
          subfinder -silent -d <domain> | dnsx -silent -a -resp
        and parses the resulting subdomains and IP addresses.
        """
        clean_domain = cls.clean_domain_target(target)
        cmd_display = f"subfinder -silent -d {clean_domain or '<domain>'} | dnsx -silent -a -resp"

        if not clean_domain:
            return {
                "executed": False,
                "available": cls.is_available(),
                "command": cmd_display,
                "target_domain": target,
                "total_discovered": 0,
                "subdomains": [],
                "discovered_ips": [],
                "error": "Target is not a valid domain name for subdomain reconnaissance."
            }

        subfinder_bin = cls._find_binary("subfinder")
        dnsx_bin = cls._find_binary("dnsx")

        if not subfinder_bin or not dnsx_bin:
            logger.warning(
                f"[SubfinderDnsxScanner] Binaries missing (subfinder={subfinder_bin}, dnsx={dnsx_bin}). "
                "Skipping subfinder|dnsx discovery."
            )
            return {
                "executed": False,
                "available": False,
                "command": cmd_display,
                "target_domain": clean_domain,
                "total_discovered": 0,
                "subdomains": [],
                "discovered_ips": [],
                "error": "subfinder or dnsx executable not found on host."
            }

        logger.info(f"[SubfinderDnsxScanner] Executing: {cmd_display} (timeout={timeout}s)")

        try:
            # We connect subfinder stdout directly to dnsx stdin using subprocess.PIPE
            p1 = subprocess.Popen(
                [subfinder_bin, "-silent", "-d", clean_domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            p2 = subprocess.Popen(
                [dnsx_bin, "-silent", "-a", "-resp"],
                stdin=p1.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if p1.stdout:
                p1.stdout.close()  # Allow p1 to receive SIGPIPE if p2 exits early

            stdout, stderr = p2.communicate(timeout=timeout)
            try:
                p1.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p1.kill()

            parsed = cls.parse_output(stdout)
            logger.info(
                f"[SubfinderDnsxScanner] Recon completed for {clean_domain}: "
                f"{len(parsed)} active subdomains parsed."
            )

            all_ips = set()
            for s in parsed:
                all_ips.update(s.get("ips", []))

            return {
                "executed": True,
                "available": True,
                "command": cmd_display,
                "target_domain": clean_domain,
                "total_discovered": len(parsed),
                "subdomains": parsed,
                "discovered_ips": sorted(list(all_ips)),
                "error": None
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"[SubfinderDnsxScanner] Timeout ({timeout}s) exceeded for {clean_domain}")
            try:
                p1.kill()
            except Exception:
                pass
            try:
                p2.kill()
            except Exception:
                pass
            return {
                "executed": True,
                "available": True,
                "command": cmd_display,
                "target_domain": clean_domain,
                "total_discovered": 0,
                "subdomains": [],
                "discovered_ips": [],
                "error": f"Execution timed out after {timeout} seconds"
            }
        except Exception as e:
            logger.error(f"[SubfinderDnsxScanner] Execution error: {e}", exc_info=True)
            return {
                "executed": False,
                "available": True,
                "command": cmd_display,
                "target_domain": clean_domain,
                "total_discovered": 0,
                "subdomains": [],
                "discovered_ips": [],
                "error": str(e)
            }
