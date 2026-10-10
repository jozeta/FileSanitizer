import re
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import unicodedata
import httpx
import dateutil.parser

from app.core.logging_config import logger

# Cache for RDAP lookups to avoid rate limiting
_RDAP_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL = 3600  # 1 hour


class DomainAnalyzer:
    """
    Comprehensive Domain, Hostname, and IP Address Intelligence Analyzer.
    Provides WHOIS/RDAP ownership, domain age, DNS records (A, AAAA, MX, NS, TXT, SOA),
    reverse DNS (PTR), co-hosted domains, homograph/Punycode visual decoding,
    and IP/URL obfuscation detection.
    """

    LOOKALIKE_MAP = {
        # Cyrillic lowercase
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'п': 'n',
        'т': 't', 'в': 'b', 'г': 'r', 'к': 'k', 'м': 'm', 'н': 'h',
        # Cyrillic uppercase
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
        'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
        # Greek
        'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
    }
    CYRILLIC_LOOKALIKES = LOOKALIKE_MAP

    DOMAIN_REGEX = re.compile(r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$')

    @classmethod
    def _is_valid_domain_string(cls, s: str) -> bool:
        """Validate if a string is a clean, legitimate domain name and not an API error or quota message."""
        if not s or not isinstance(s, str):
            return False
        clean = s.strip().lower()
        if len(clean) > 253 or " " in clean or "\t" in clean or "\n" in clean:
            return False
        # Filter out HackerTarget or other API error messages
        bad_tokens = ["quota", "exceeded", "limit", "membership", "error", "hackertarget", "api count", "cloudflare", "rate limit"]
        if any(tok in clean for tok in bad_tokens):
            return False
        return bool(cls.DOMAIN_REGEX.match(clean))

    @classmethod
    def analyze(cls, target: str, deep: bool = False) -> Dict[str, Any]:
        """
        Analyze a domain or IP address.

        With deep=True (explicit domain/IP lookups) the Autonomous System, corporate network
        block and owned IPs are used to discover other domains held by the same owner
        (see app.analyzers.domain_relations).
        """
        clean_target = cls._normalize_target(target)
        is_ip = cls._is_ip_address(clean_target)

        res: Dict[str, Any] = {
            "target": clean_target,
            "is_ip": is_ip,
            "punycode_analysis": {},
            "obfuscation_analysis": {},
            "dns_records": {},
            "whois": {},
            "network": {},
            "co_hosted_domains": [],
            "owner_intelligence": {},
            "related_domains": [],
            "ownership_pivots": {},
            "risk_flags": []
        }

        # 1. Punycode & Homograph Analysis
        if not is_ip:
            punycode_info = cls.analyze_punycode(clean_target)
            res["punycode_analysis"] = punycode_info
            if punycode_info.get("is_homograph"):
                res["risk_flags"].append({
                    "severity": "critical",
                    "title": "Homograph Impersonation Attack Detected",
                    "description": f"Domain uses Punycode '{clean_target}' to impersonate '{punycode_info.get('unicode_rendered')}' using non-ASCII lookalike characters."
                })

        # 2. Obfuscation Analysis
        obf = cls.detect_obfuscation(target)
        res["obfuscation_analysis"] = obf
        if obf.get("is_obfuscated"):
            for t in obf.get("techniques", []):
                res["risk_flags"].append({
                    "severity": "high",
                    "title": f"Obfuscated Address Format: {t.get('name')}",
                    "description": t.get("description", "")
                })

        # 3. DNS Records Resolution
        dns_data = cls.resolve_dns(clean_target, is_ip=is_ip)
        res["dns_records"] = dns_data

        # 4. WHOIS / RDAP Registration Intelligence
        whois_data = cls.query_rdap_whois(clean_target, is_ip=is_ip)
        res["whois"] = whois_data

        # Check domain age risk
        domain_age_days = whois_data.get("domain_age_days")
        if domain_age_days is not None and domain_age_days < 30:
            res["risk_flags"].append({
                "severity": "high",
                "title": f"Newly Registered Domain ({domain_age_days} Days Old)",
                "description": f"Domain was registered very recently on {whois_data.get('registration_date', 'recent')}. Newly registered domains are disproportionately used in phishing and malware campaigns."
            })

        # 5. Reverse IP & Co-hosted Domains
        resolved_ips = dns_data.get("a", []) if not is_ip else [clean_target]
        primary_ip = resolved_ips[0] if resolved_ips else (clean_target if is_ip else None)

        sibling_domains: List[str] = []
        if primary_ip:
            co_hosted, net_info = cls.query_reverse_ip_and_asn(primary_ip)
            # Filter co-hosted strictly to valid domains
            res["co_hosted_domains"] = [d for d in co_hosted if cls._is_valid_domain_string(d)]
            res["network"] = net_info

            # Discover sibling / related domains owned by the same organization
            root_domain = cls.get_registered_domain(clean_target) if not is_ip else None
            if root_domain and not cls._is_ip_address(root_domain):
                try:
                    with httpx.Client(timeout=3.0) as client:
                        ht_resp = client.get(f"https://api.hackertarget.com/hostsearch/?q={root_domain}")
                        if ht_resp.status_code == 200 and not ht_resp.text.lower().startswith("error"):
                            for line in ht_resp.text.splitlines():
                                parts = line.split(",")
                                if parts:
                                    h = parts[0].strip().lower()
                                    if cls._is_valid_domain_string(h) and h not in sibling_domains:
                                        sibling_domains.append(h)
                except Exception:
                    pass

        # 6. Corporate & Owner Intelligence Synthesis
        owner_name = (
            whois_data.get("registrant_org")
            or (res["network"].get("org") if res.get("network") else None)
            or whois_data.get("registrar")
            or "Unknown Registrant"
        )
        ip_ranges: List[str] = []
        if res.get("network") and res["network"].get("ip_range"):
            ip_ranges.append(res["network"]["ip_range"])
        if res.get("network") and res["network"].get("cidrs"):
            for c in res["network"]["cidrs"]:
                if c not in ip_ranges:
                    ip_ranges.append(c)
        if whois_data.get("ip_range") and whois_data["ip_range"] not in ip_ranges:
            ip_ranges.append(whois_data["ip_range"])
        for c in whois_data.get("cidrs", []):
            if c not in ip_ranges:
                ip_ranges.append(c)

        res["owner_intelligence"] = {
            "owner_name": owner_name,
            "organization": whois_data.get("registrant_org") or (res["network"].get("org") if res.get("network") else None),
            "registrar": whois_data.get("registrar"),
            "network_name": (res["network"].get("network_name") if res.get("network") else None) or whois_data.get("network_name"),
            "asn": (res["network"].get("asn") if res.get("network") else None),
            "asn_org": (res["network"].get("as_org") if res.get("network") else None) or (res["network"].get("org") if res.get("network") else None),
            "isp": (res["network"].get("isp") if res.get("network") else None),
            "ip_range": (res["network"].get("ip_range") if res.get("network") else None) or whois_data.get("ip_range"),
            "cidrs": (res["network"].get("cidrs") if res.get("network") else None) or whois_data.get("cidrs", []),
            "more_domains": sibling_domains[:30],
            "more_ip_ranges": ip_ranges[:15]
        }

        # 7. Ownership pivoting: ASN + corporate network + owned IPs -> other domains of same owner
        if deep:
            try:
                from app.analyzers.domain_relations import DomainRelationDiscovery
                rel = DomainRelationDiscovery.discover(
                    target=clean_target,
                    is_ip=is_ip,
                    resolved_ips=resolved_ips,
                    dns_data=dns_data,
                    whois_data=whois_data,
                    net_info=res.get("network") or {},
                    co_hosted_primary=res["co_hosted_domains"],
                    primary_ip=primary_ip,
                    sibling_domains=sibling_domains,
                )
                res["related_domains"] = rel["related_domains"]
                res["ownership_pivots"] = rel["ownership_pivots"]

                oi = res["owner_intelligence"]
                merged_domains: List[str] = list(sibling_domains)
                for r in rel["related_domains"]:
                    # Co-hosting on shared IPs alone is weak evidence of common ownership
                    if r["confidence"] != "low" and r["domain"] not in merged_domains:
                        merged_domains.append(r["domain"])
                oi["more_domains"] = merged_domains[:60]
                for rng in rel["ownership_pivots"].get("asn_prefixes", [])[:10]:
                    if rng not in ip_ranges:
                        ip_ranges.append(rng)
                oi["more_ip_ranges"] = ip_ranges[:25]
                if not oi.get("asn") and rel["ownership_pivots"].get("asn"):
                    oi["asn"] = rel["ownership_pivots"]["asn"]
            except Exception as e:
                logger.warning(f"Related-domain discovery failed for {clean_target}: {e}")

        return res


    @classmethod
    def _normalize_target(cls, target: str) -> str:
        """Strip protocol and path from target."""
        raw = target.strip()
        if "://" in raw:
            try:
                parsed = urllib.parse.urlparse(raw)
                return parsed.netloc.split(":")[0].strip().lower()
            except Exception:
                pass
        # Strip trailing paths/slashes
        raw = raw.split("/")[0].split(":")[0].strip().lower()
        return raw

    @classmethod
    def _is_ip_address(cls, target: str) -> bool:
        """Check if target is a valid IPv4 or IPv6 address."""
        try:
            socket.inet_aton(target)
            return True
        except Exception:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except Exception:
                return False

    @classmethod
    def get_registered_domain(cls, domain: str) -> str:
        """
        Extract the root registrable domain from a subdomain/hostname.
        E.g., 'www.folksam.se' -> 'folksam.se', 'sub.blog.google.com' -> 'google.com'
        """
        clean = domain.strip().lower()
        if cls._is_ip_address(clean):
            return clean

        parts = clean.split(".")
        if len(parts) <= 2:
            return clean

        second_level_tlds = {
            "co", "com", "org", "net", "edu", "gov", "mil", "ac", "asso", "nom", "pp", "tm"
        }
        if len(parts) >= 3 and parts[-2] in second_level_tlds and len(parts[-1]) == 2:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    @classmethod
    def analyze_punycode(cls, domain: str) -> Dict[str, Any]:
        """
        Detect Punycode and Unicode lookalike homoglyphs.
        Returns decoded representation and highlighted lookalikes.
        """
        is_punycode = "xn--" in domain.lower()
        unicode_rendered = domain

        try:
            if is_punycode:
                unicode_rendered = domain.encode("ascii").decode("idna")
        except Exception:
            pass

        spoofed_chars: List[Dict[str, Any]] = []
        is_homograph = False

        for ch in unicode_rendered:
            if ord(ch) > 127:
                name = unicodedata.name(ch, "UNKNOWN CHARACTER")
                latin = cls.CYRILLIC_LOOKALIKES.get(ch, "")
                spoofed_chars.append({
                    "char": ch,
                    "codepoint": f"U+{ord(ch):04X}",
                    "name": name,
                    "latin_lookalike": latin
                })
                is_homograph = True

        simulated_latin = "".join(cls.LOOKALIKE_MAP.get(ch, ch) for ch in unicode_rendered)
        # Visual appearance rendered with the actual special characters (e.g. Cyrillic lookalikes)
        visual_appearance = unicode_rendered

        return {
            "is_punycode": is_punycode,
            "punycode": domain,
            "unicode_rendered": unicode_rendered,
            "visual_appearance": visual_appearance,
            "simulated_latin": simulated_latin,
            "is_homograph": is_homograph,
            "spoofed_chars": spoofed_chars,
            "display_warning": f"Punycode '{domain}' visually renders as '{unicode_rendered}' (masquerading as '{simulated_latin}')" if is_homograph else None
        }

    @classmethod
    def detect_obfuscation(cls, raw: str) -> Dict[str, Any]:
        """
        Detect IP and URL obfuscation methods used by attackers.
        """
        techniques: List[Dict[str, Any]] = []
        clean = raw.strip()

        # Dword IP (e.g. http://2130706433 or 2130706433)
        dword_m = re.search(r'(?:https?://)?(\d{8,11})(?:/|$)', clean)
        if dword_m:
            try:
                num = int(dword_m.group(1))
                if 0 < num < 4294967295:
                    ip = socket.inet_ntoa(num.to_bytes(4, byteorder='big'))
                    techniques.append({
                        "type": "DWORD_IP",
                        "name": "Integer / Dword IP Obfuscation",
                        "description": f"Dword decimal {num} resolves to dotted-decimal IPv4 {ip}."
                    })
            except Exception:
                pass

        # Hex IP (e.g. 0x7f.0x0.0x0.0x1 or 0x7f000001)
        if "0x" in clean.lower():
            techniques.append({
                "type": "HEX_IP",
                "name": "Hexadecimal IP Representation",
                "description": "IP or address utilizes hexadecimal components to evade URL filters."
            })

        # Octal IP (e.g. 0177.0.0.1)
        if re.search(r'\b0\d{2,3}\.', clean):
            techniques.append({
                "type": "OCTAL_IP",
                "name": "Octal IP Representation",
                "description": "IP utilizes leading zeros to trigger octal parsing evasion."
            })

        # Userinfo credential trick (e.g. http://safe.com@evil.com)
        if "@" in clean and "://" in clean:
            techniques.append({
                "type": "USERINFO_SPOOFING",
                "name": "URL Userinfo '@' Spoofing",
                "description": "URL includes simulated safe domain before an '@' delimiter to mislead users."
            })

        # Double URL encoding
        if re.search(r'%25[0-9a-fA-F]{2}', clean):
            techniques.append({
                "type": "DOUBLE_URL_ENCODING",
                "name": "Double URL Encoding",
                "description": "URL parameters contain multi-layered %25 hex escapes."
            })

        return {
            "is_obfuscated": len(techniques) > 0,
            "techniques": techniques
        }

    @classmethod
    def resolve_dns(cls, domain: str, is_ip: bool = False) -> Dict[str, Any]:
        """
        Query comprehensive DNS records using dnspython or socket fallback.
        """
        records: Dict[str, Any] = {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": [],
            "ptr": []
        }

        try:
            import dns.resolver
            import dns.reversename

            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 4.0

            if is_ip:
                # Reverse PTR
                try:
                    rev_name = dns.reversename.from_address(domain)
                    ptr_ans = resolver.resolve(rev_name, "PTR")
                    records["ptr"] = [str(r).rstrip(".") for r in ptr_ans]
                except Exception:
                    pass
                return records

            # A Records
            try:
                a_ans = resolver.resolve(domain, "A")
                records["a"] = [str(r) for r in a_ans]
            except Exception:
                pass

            # AAAA Records
            try:
                aaaa_ans = resolver.resolve(domain, "AAAA")
                records["aaaa"] = [str(r) for r in aaaa_ans]
            except Exception:
                pass

            # MX Records
            try:
                mx_ans = resolver.resolve(domain, "MX")
                records["mx"] = [
                    {"host": str(r.exchange).rstrip("."), "priority": r.preference}
                    for r in sorted(mx_ans, key=lambda x: x.preference)
                ]
            except Exception:
                pass

            # NS Records
            try:
                ns_ans = resolver.resolve(domain, "NS")
                records["ns"] = [str(r).rstrip(".") for r in ns_ans]
            except Exception:
                pass

            # TXT Records
            try:
                txt_ans = resolver.resolve(domain, "TXT")
                records["txt"] = [r.to_text().strip('"') for r in txt_ans]
            except Exception:
                pass

            # CNAME
            try:
                cname_ans = resolver.resolve(domain, "CNAME")
                records["cname"] = [str(r).rstrip(".") for r in cname_ans]
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"DNS resolver fallback note: {e}")
            # Standard socket fallback for A records
            if not is_ip:
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    records["a"] = ips
                except Exception:
                    pass

        return records

    @classmethod
    def query_socket_whois(cls, domain: str) -> Optional[Dict[str, Any]]:
        """
        Direct socket port 43 WHOIS query with IANA referral fallback.
        Accurately extracts registration date, registrar, expiration, and nameservers
        for ccTLDs (.se, .nu, .de, .eu, etc.) unsupported or 404 by RDAP.
        """
        clean = domain.strip().lower()
        parts = clean.split('.')
        if len(parts) < 2:
            return None
        tld = parts[-1]

        KNOWN_SERVERS = {
            'se': 'whois.iis.se',
            'nu': 'whois.iis.nu',
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'de': 'whois.denic.de',
            'uk': 'whois.nic.uk',
            'eu': 'whois.eu',
            'no': 'whois.norid.no',
            'dk': 'whois.dk-hostmaster.dk',
            'fi': 'whois.fi',
            'io': 'whois.nic.io',
            'ai': 'whois.nic.ai',
            'me': 'whois.nic.me',
            'ca': 'whois.cira.ca',
            'ch': 'whois.nic.ch',
            'at': 'whois.nic.at',
            'fr': 'whois.nic.fr',
            'it': 'whois.nic.it',
            'nl': 'whois.domain-registry.nl',
            'be': 'whois.dns.be',
            'pl': 'whois.dns.pl',
            'cz': 'whois.nic.cz',
            'ru': 'whois.tcinet.ru',
            'info': 'whois.afilias.net',
            'biz': 'whois.nic.biz',
            'app': 'whois.nic.google',
            'dev': 'whois.nic.google',
        }

        whois_server = KNOWN_SERVERS.get(tld)
        if not whois_server:
            try:
                s = socket.create_connection(('whois.iana.org', 43), timeout=3.0)
                s.sendall(f"{tld}\r\n".encode('idna'))
                resp = b""
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    resp += d
                s.close()
                m = re.search(r'whois:\s*(\S+)', resp.decode('utf-8', errors='ignore'), re.I)
                if m:
                    whois_server = m.group(1).strip()
            except Exception as e:
                logger.debug(f"IANA referral lookup failed for {tld}: {e}")

        if not whois_server:
            return None

        try:
            s = socket.create_connection((whois_server, 43), timeout=4.0)
            s.sendall(f"{clean}\r\n".encode('idna'))
            resp = b""
            while True:
                d = s.recv(4096)
                if not d:
                    break
                resp += d
            s.close()
            text = resp.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Socket WHOIS query failed for {clean} at {whois_server}: {e}")
            return None

        res: Dict[str, Any] = {
            "registrar": None,
            "registration_date": None,
            "expiration_date": None,
            "last_updated": None,
            "nameservers": [],
            "dnssec": False,
            "registrant_org": None,
        }

        # Registration / Creation Date
        m_reg = re.search(r'(?:created|creation date|registered|registration date|domain record activated):\s*([^\r\n]+)', text, re.I)
        if m_reg:
            res['registration_date'] = m_reg.group(1).strip()

        # Expiration Date
        m_exp = re.search(r'(?:expires|expiration date|registry expiry date|paid-till):\s*([^\r\n]+)', text, re.I)
        if m_exp:
            res['expiration_date'] = m_exp.group(1).strip()

        # Last Modified Date
        m_mod = re.search(r'(?:modified|updated date|last updated):\s*([^\r\n]+)', text, re.I)
        if m_mod:
            res['last_updated'] = m_mod.group(1).strip()

        # Registrar
        m_regtr = re.search(r'(?:registrar|registrar name|sponsoring registrar):\s*([^\r\n]+)', text, re.I)
        if m_regtr:
            res['registrar'] = m_regtr.group(1).strip()

        # Registrant / Org / Holder
        m_org = re.search(r'(?:registrant(?:\s+organization)?|org|holder):\s*([^\r\n]+)', text, re.I)
        if m_org:
            res['registrant_org'] = m_org.group(1).strip()

        # Nameservers
        for ns_m in re.finditer(r'(?:nserver|name server):\s*([^\s\r\n]+)', text, re.I):
            ns_val = ns_m.group(1).strip().rstrip('.').lower()
            if ns_val and ns_val not in res['nameservers']:
                res['nameservers'].append(ns_val)

        # DNSSEC
        if re.search(r'dnssec:\s*(?:signed|yes|active|delegation signed)', text, re.I):
            res['dnssec'] = True

        return res

    @classmethod
    def query_rdap_whois(cls, target: str, is_ip: bool = False) -> Dict[str, Any]:
        """
        Query official ICANN RDAP protocol with socket port 43 WHOIS fallback.
        Accurately extracts registration metadata, registrar, dates, and ownership.
        """
        now = datetime.now(timezone.utc).timestamp()
        cache_key = f"rdap:{target}"
        if cache_key in _RDAP_CACHE:
            ts, cached = _RDAP_CACHE[cache_key]
            if now - ts < _CACHE_TTL:
                return cached

        lookup_target = target if is_ip else cls.get_registered_domain(target)
        endpoint = f"https://rdap.org/ip/{target}" if is_ip else f"https://rdap.org/domain/{lookup_target}"

        data: Dict[str, Any] = {
            "target": target,
            "status": "UNAVAILABLE",
            "registrar": "Unknown",
            "registration_date": None,
            "creation_date": None,
            "expiration_date": None,
            "last_updated": None,
            "domain_age_days": None,
            "domain_age_formatted": None,
            "registrant_country": None,
            "registrant_org": None,
            "nameservers": [],
            "dnssec": False,
            "network_name": None,
            "start_address": None,
            "end_address": None,
            "ip_range": None,
            "cidrs": []
        }

        try:
            with httpx.Client(timeout=4.5, follow_redirects=True) as client:
                resp = client.get(endpoint)
                if resp.status_code == 200:
                    rdap = resp.json()
                    data["status"] = "ACTIVE"

                    if is_ip:
                        data["network_name"] = rdap.get("name")
                        start_addr = rdap.get("startAddress")
                        end_addr = rdap.get("endAddress")
                        data["start_address"] = start_addr
                        data["end_address"] = end_addr
                        if start_addr and end_addr:
                            data["ip_range"] = f"{start_addr} - {end_addr}"
                        cidrs = []
                        for c in rdap.get("cidr0_cidrs", []):
                            if "v4prefix" in c and "length" in c:
                                cidrs.append(f"{c['v4prefix']}/{c['length']}")
                            elif "v6prefix" in c and "length" in c:
                                cidrs.append(f"{c['v6prefix']}/{c['length']}")
                        data["cidrs"] = cidrs

                    # Parse Events (registration, expiration, last changed)
                    events = rdap.get("events", [])
                    for ev in events:
                        action = ev.get("eventAction", "").lower()
                        date_str = ev.get("eventDate")
                        if not date_str:
                            continue
                        if action == "registration":
                            data["registration_date"] = date_str
                        elif action == "expiration":
                            data["expiration_date"] = date_str
                        elif action in ["last changed", "last update"]:
                            data["last_updated"] = date_str

                    # Parse Registrar & Entities
                    for entity in rdap.get("entities", []):
                        roles = entity.get("roles", [])
                        vcard = entity.get("vcardArray", [])
                        fn = None
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    fn = prop[3]
                        if "registrar" in roles and fn:
                            data["registrar"] = fn
                        if "registrant" in roles and fn:
                            # Registry contact handles (e.g. "CP0000-27873") are identifiers, not organization names
                            is_handle = bool(re.fullmatch(r'[A-Za-z0-9_\-]{4,}', fn.strip())) and bool(re.search(r'\d', fn))
                            if not is_handle:
                                data["registrant_org"] = fn

                    # Nameservers from RDAP
                    for ns in rdap.get("nameservers", []):
                        ns_name = ns.get("ldhName") or ns.get("unicodeName")
                        if ns_name:
                            data["nameservers"].append(ns_name.lower())

                    # DNSSEC
                    secure_dns = rdap.get("secureDNS", {})
                    data["dnssec"] = secure_dns.get("delegationSigned", False)

        except Exception as e:
            logger.debug(f"RDAP query note for {target}: {e}")

        # Fallback to direct socket WHOIS on port 43 if registration_date was not found and target is not an IP
        if not is_ip and (data["registration_date"] is None or data["status"] == "UNAVAILABLE"):
            try:
                socket_res = cls.query_socket_whois(lookup_target)
                if socket_res and (socket_res.get("registration_date") or socket_res.get("registrar")):
                    data["status"] = "ACTIVE"
                    if socket_res.get("registration_date") and not data.get("registration_date"):
                        data["registration_date"] = socket_res["registration_date"]
                    if socket_res.get("expiration_date") and not data.get("expiration_date"):
                        data["expiration_date"] = socket_res["expiration_date"]
                    if socket_res.get("last_updated") and not data.get("last_updated"):
                        data["last_updated"] = socket_res["last_updated"]
                    if socket_res.get("registrar") and (not data.get("registrar") or data["registrar"] == "Unknown"):
                        data["registrar"] = socket_res["registrar"]
                    if socket_res.get("registrant_org") and not data.get("registrant_org"):
                        data["registrant_org"] = socket_res["registrant_org"]
                    if socket_res.get("nameservers") and not data.get("nameservers"):
                        data["nameservers"] = socket_res["nameservers"]
                    if socket_res.get("dnssec"):
                        data["dnssec"] = True
            except Exception as e:
                logger.debug(f"Socket WHOIS fallback error for {target}: {e}")

        # Registry contact handles (e.g. .se "CP0000-27873") are identifiers, not organization names
        reg_org = (data.get("registrant_org") or "").strip()
        if reg_org and " " not in reg_org and re.fullmatch(r'[A-Za-z0-9_\-]{4,}', reg_org) and re.search(r'\d', reg_org):
            data["registrant_handle"] = reg_org
            data["registrant_org"] = None

        # Calculate Domain Age from registration_date
        if data.get("registration_date"):
            try:
                reg_dt = dateutil.parser.parse(data["registration_date"])
                if reg_dt.tzinfo is None:
                    reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                delta = now_dt - reg_dt
                days = delta.days
                data["domain_age_days"] = max(0, days)
                years = days // 365
                months = (days % 365) // 30
                if years > 0:
                    data["domain_age_formatted"] = f"{years} year{'s' if years > 1 else ''}, {months} month{'s' if months > 1 else ''} ({days} days)"
                else:
                    data["domain_age_formatted"] = f"{days} days"
            except Exception as e:
                logger.debug(f"Domain age parse error for {target}: {e}")

        # Backward compatibility alias
        data["creation_date"] = data.get("registration_date")

        _RDAP_CACHE[cache_key] = (now, data)
        return data

    @classmethod
    def query_reverse_ip_and_asn(cls, ip: str) -> Tuple[List[str], Dict[str, Any]]:
        """
        Resolve IP to PTR, ASN, ISP, network blocks, and discover passive co-hosted domains.
        """
        co_hosted: List[str] = []
        net_info: Dict[str, Any] = {
            "ip": ip,
            "hostname": None,
            "asn": None,
            "as_org": None,
            "org": None,
            "isp": None,
            "network_name": None,
            "ip_range": None,
            "cidrs": [],
            "country": None,
            "city": None
        }

        # 1. PTR Reverse DNS
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            net_info["hostname"] = host
            if host and host != ip and cls._is_valid_domain_string(host):
                co_hosted.append(host.lower())
        except Exception:
            pass

        # 2. Query RDAP for IP network info & CIDRs
        try:
            rdap = cls.query_rdap_whois(ip, is_ip=True)
            if rdap.get("registrant_org"):
                net_info["org"] = rdap["registrant_org"]
            if rdap.get("network_name"):
                net_info["network_name"] = rdap["network_name"]
            if rdap.get("ip_range"):
                net_info["ip_range"] = rdap["ip_range"]
            if rdap.get("cidrs"):
                net_info["cidrs"] = rdap["cidrs"]
        except Exception:
            pass

        # 3. Query ip-api.com for ASN, ISP, Org, Country, City (3s timeout)
        try:
            with httpx.Client(timeout=3.0) as client:
                api_resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,asname")
                if api_resp.status_code == 200:
                    api_data = api_resp.json()
                    if api_data.get("status") == "success":
                        if api_data.get("as"):
                            net_info["asn"] = api_data["as"].split()[0]
                            net_info["as_org"] = api_data["as"]
                        if api_data.get("isp") and not net_info.get("isp"):
                            net_info["isp"] = api_data["isp"]
                        if api_data.get("org") and not net_info.get("org"):
                            net_info["org"] = api_data["org"]
                        if api_data.get("country") and not net_info.get("country"):
                            net_info["country"] = api_data["country"]
                        if api_data.get("city") and not net_info.get("city"):
                            net_info["city"] = api_data["city"]
        except Exception:
            pass

        # 4. Query HackerTarget free reverse IP API (with 3-second timeout)
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
                if resp.status_code == 200:
                    text_lower = resp.text.lower()
                    if not text_lower.startswith("error") and "api count exceeded" not in text_lower:
                        for line in resp.text.splitlines():
                            d = line.strip().lower()
                            if cls._is_valid_domain_string(d) and d not in co_hosted:
                                co_hosted.append(d)
        except Exception:
            pass

        # 5. HackerTarget AS lookup for CIDR subnet check
        try:
            with httpx.Client(timeout=3.0) as client:
                as_resp = client.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
                if as_resp.status_code == 200 and not as_resp.text.lower().startswith("error"):
                    # Format: "193.183.161.1","42649","193.183.161.0/24","BBN, SE"
                    parts = [p.strip().strip('"') for p in as_resp.text.split(",")]
                    if len(parts) >= 3:
                        cidr = parts[2]
                        if "/" in cidr and cidr not in net_info["cidrs"]:
                            net_info["cidrs"].append(cidr)
                        if not net_info.get("asn") and parts[1]:
                            net_info["asn"] = f"AS{parts[1]}"
        except Exception:
            pass

        return co_hosted, net_info
