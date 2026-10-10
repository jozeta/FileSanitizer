"""
Ownership pivoting for domain / IP lookups.

Given the facts already gathered by DomainAnalyzer (resolved IPs, ASN, network block,
registrant, DNS records) this module pivots on them to discover *other* domains that
are likely controlled by the same entity.

Pivots (all passive - nothing is sent to the target's own infrastructure):

  * Certificate Transparency  - SAN co-listing: domains sharing a TLS certificate with the target
  * Certificate Transparency  - certificates issued to the same registrant / AS-holder organization
  * Same IP                   - reverse-IP lookups for every resolved address
  * Same corporate network    - reverse-DNS (PTR) sweep of the CIDR block the IP is allocated in
  * Same Autonomous System    - PTR sampling across the other prefixes announced by the ASN
                                (skipped for shared hosting / cloud / CDN ASNs, because the AS
                                 holder there is NOT the owner of the hosted domains)
  * DNS policy records        - SPF includes/redirects, vanity nameservers, self-hosted MX

Every discovered domain carries the relationship(s), the evidence and a confidence rating.
Confidence is raised when independent pivots corroborate each other.
"""
import ipaddress
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from app.core.logging_config import logger

_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL = 3600
_TOTAL_BUDGET_S = 30.0
_PHASE1_BUDGET_S = 17.0

CONF_RANK = {"low": 1, "medium": 2, "high": 3}
CONF_NAME = {1: "low", 2: "medium", 3: "high"}

RELATIONSHIP_LABELS = {
    "shared_certificate": "Co-listed in same TLS certificate",
    "cert_organization": "Certificate issued to same organization",
    "spf_reference": "Referenced in SPF mail policy",
    "mx_infrastructure": "Operates the target's mail exchangers",
    "custom_nameserver": "Hosts the target's vanity nameservers",
    "as_operator": "Operator of the Autonomous System (network provider)",
    "same_ip": "Hosted on same IP address",
    "same_network": "Same corporate network block",
    "same_asn": "Same Autonomous System",
}

# AS holders / hosts where "same ASN" or "same netblock" does NOT imply "same owner"
SHARED_INFRA_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "akamai", "fastly",
    "digitalocean", "digital ocean", "ovh", "hetzner", "linode", "vultr", "oracle",
    "alibaba", "tencent", "godaddy", "namecheap", "hostinger", "contabo", "leaseweb",
    "choopa", "rackspace", "scaleway", "ionos", "1&1", "bluehost", "hostgator",
    "dreamhost", "siteground", "wix", "squarespace", "shopify", "automattic", "github",
    "netlify", "vercel", "heroku", "incapsula", "imperva", "sucuri", "stackpath", "cdn77",
    "bunny", "m247", "psychz", "quadranet", "colocrossing", "hostwinds", "datacamp",
    "zenlayer", "frantech", "selectel", "timeweb", "reg.ru", "beget", "aruba", "strato",
    "hostpoint", "one.com", "gandi", "equinix", "cogent", "level 3", "lumen", "hurricane",
    "choopa", "servers.com", "interserver", "liquid web", "ramnode", "kamatera",
)

GENERIC_REGISTRANT_TOKENS = (
    "redacted", "privacy", "whois", "proxy", "withheld", "data protected", "not disclosed",
    "gdpr", "domains by proxy", "contact privacy", "identity protect", "unknown",
    "private registration", "registration private", "statutory masking",
)

# Mail / SaaS platforms: referencing them in SPF says nothing about ownership
KNOWN_MAIL_PLATFORMS = (
    "google.com", "googlemail.com", "outlook.com", "office365.com", "microsoft.com",
    "sendgrid.net", "mailgun.org", "mailchimp.com", "mcsv.net", "mandrillapp.com",
    "amazonses.com", "zoho.com", "zoho.eu", "salesforce.com", "secureserver.net",
    "pphosted.com", "mimecast.com", "messagelabs.com", "sparkpostmail.com", "hubspot.com",
    "zendesk.net", "freshdesk.com", "mailjet.com", "postmarkapp.com", "icloud.com",
    "yahoodns.net", "cloudflare.net", "protection.outlook.com", "emailsrvr.com",
    "forcepoint.net", "barracudanetworks.com", "proofpoint.com", "ppe-hosted.com",
    "mailanyone.net", "rackspace.com", "fastmail.com", "messagingengine.com",
    "mxlogic.net", "mtasv.net", "sendinblue.com", "brevo.com", "constantcontact.com",
    "cmail1.com", "cmail2.com", "createsend.com", "mktomail.com", "marketo.com",
    "eloqua.com", "exacttarget.com", "mailgun.net", "spf.mandrillapp.com", "yandex.net",
    "yandex.ru", "mail.ru", "qq.com", "163.com", "gandi.net", "ovh.net", "one.com",
    "binero.se", "loopia.se", "bahnhof.se", "telia.com", "ionos.com", "kundenserver.de",
    "hostinger.com", "titan.email", "registrar-servers.com", "dnsowl.com", "1and1.com",
)

# DNS providers: vanity-NS detection must ignore them
KNOWN_DNS_PROVIDERS = (
    "cloudflare.com", "awsdns-", "amazonaws.com", "azure-dns.", "google.com", "googledomains.com",
    "domaincontrol.com", "registrar-servers.com", "dnsmadeeasy.com", "ultradns.net", "ultradns.com", "ultradns.org", "nsone.net",
    "dynect.net", "godaddy.com", "gandi.net", "ovh.net", "hetzner.com", "hetzner.de",
    "digitalocean.com", "linode.com", "vultr.com", "akam.net", "akamai.net", "worldnic.com",
    "name-services.com", "dnsv.jp", "he.net", "afraid.org", "rackspace.com", "bluehost.com",
    "hostgator.com", "wixdns.net", "squarespace.com", "netlify.com", "vercel-dns.com",
    "dnsimple.com", "easydns.com", "easydns.net", "markmonitor.com", "csc.com",
    "cscdns.net", "cscglobal.com", "networksolutions.com", "ionos.com", "ui-dns.", "1and1.com",
    "loopia.se", "binero.se", "one.com", "telia.com", "tele2.com", "bahnhof.net", "namecheap.com", "porkbun.com", "hover.com",
    "inwx.de", "inwx.com", "dnspod.net", "dnspod.com", "alidns.com", "hichina.com", "verisigndns.com",
)

# PTR suffixes that identify cloud/ISP infrastructure rather than a customer's own domain
INFRA_PTR_DOMAINS = (
    "amazonaws.com", "googleusercontent.com", "cloudfront.net", "azure.com", "azurewebsites.net",
    "akamaitechnologies.com", "linodeusercontent.com", "your-server.de", "ovh.net", "ovh.com",
    "hetzner.com", "digitalocean.com", "comcast.net", "rr.com", "verizon.net", "bc.googleusercontent.com",
    "compute.amazonaws.com", "secureserver.net", "cloudflare.com", "vultrusercontent.com",
    "contaboserver.net", "kimsufi.com", "scaleway.com", "fastly.net", "ip-addr.dev",
)

ASN_OVERLARGE_PREFIX_COUNT = 150
MAX_RESULTS = 150


def _is_domain_suffix(domain: str, suffixes: Tuple[str, ...]) -> bool:
    """Domain-suffix match; entries ending in '-' or '.' are treated as substring fragments."""
    d = (domain or "").lower().rstrip(".")
    for s in suffixes:
        s = s.lower()
        if s.endswith(("-", ".")):
            if s in d:
                return True
        elif d == s or d.endswith("." + s):
            return True
    return False


def _is_shared_infra(text: str) -> Optional[str]:
    low = (text or "").lower()
    for kw in SHARED_INFRA_KEYWORDS:
        if kw in low:
            return kw
    return None


def _usable_registrant(org: Optional[str]) -> bool:
    if not org or len(org.strip()) < 3:
        return False
    # Registry contact handles such as "CP0000-27873" are identifiers, not organization names
    if re.fullmatch(r'[A-Za-z0-9_\-]{4,}', org.strip()) and re.search(r'\d', org) and " " not in org.strip():
        return False
    low = org.lower()
    return not any(t in low for t in GENERIC_REGISTRANT_TOKENS)


_HOLDER_STOPWORDS = {
    "ab", "as", "a/s", "ltd", "llc", "inc", "gmbh", "bv", "oy", "sa", "sas", "plc", "co", "the", "and",
    "network", "networks", "telecom", "telecommunications", "communications", "internet", "services",
    "service", "hosting", "group", "holding", "limited", "corporation", "corp", "company", "data",
}


def _holder_keys(holder: str) -> List[str]:
    words = re.findall(r'[a-z0-9]+', (holder or "").lower())
    return [w for w in words if w not in _HOLDER_STOPWORDS and len(w) >= 4][:2]


def _looks_like_as_operator(reg_domain: str, holder: str) -> bool:
    """True when the domain is the network provider itself (e.g. baffinbaynetworks.com for 'Baffin Bay Networks AB')."""
    name = reg_domain.lower().split(".")[0].replace("-", "")
    joined = "".join(re.findall(r'[a-z0-9]+', (holder or "").lower()))
    keys = _holder_keys(holder)
    if keys and (all(k in name for k in keys[:2]) or (joined and name and (name in joined or joined.startswith(name)) and len(name) >= 5)):
        return True
    return False


def _clean_as_holder(text: Optional[str]) -> str:
    """'AS42649 BBN Intressenter AB' -> 'BBN Intressenter AB'."""
    if not text:
        return ""
    return re.sub(r'^\s*AS\d+\s*[-:]?\s*', '', text).strip()


def _is_generic_ptr(host: str, ip: str) -> bool:
    """Auto-generated ISP / cloud reverse names that carry no ownership information."""
    h = host.lower()
    octets = ip.split(".")
    if len(octets) == 4:
        variants = {
            "-".join(octets), "-".join(reversed(octets)),
            ".".join(octets), ".".join(reversed(octets)),
        }
        if any(v in h for v in variants):
            return True
    first = h.split(".")[0]
    if len(re.findall(r'\d+', first)) >= 3:
        return True
    return bool(re.match(r'^(?:ip|host|static|dyn|dynamic|dhcp|pool|dsl|adsl|cable|cust|customer|'
                         r'broadband|vps|cpe|ppp|nat|pc|client)[-_]?\d', first))


def _sample_hosts(net: "ipaddress.IPv4Network", count: int) -> List[str]:
    total = net.num_addresses
    if total <= 2:
        return [str(a) for a in net]
    if total - 2 <= count:
        return [str(h) for h in net.hosts()]
    step = max(1, (total - 2) // count)
    out: List[str] = []
    for i in range(1, total - 1, step):
        out.append(str(net.network_address + i))
        if len(out) >= count:
            break
    return out


def _to_ipv4_networks(prefixes: List[str]) -> List["ipaddress.IPv4Network"]:
    nets = []
    for p in prefixes:
        try:
            n = ipaddress.ip_network(p, strict=False)
            if isinstance(n, ipaddress.IPv4Network):
                nets.append(n)
        except ValueError:
            continue
    return nets


class _Collector:
    """Merges hits from independent pivots per registered domain."""

    def __init__(self, target: str, root: str, registered: Callable[[str], str], is_valid: Callable[[str], bool]):
        self.target = target
        self.root = root
        self.registered = registered
        self.is_valid = is_valid
        self.items: Dict[str, Dict[str, Any]] = {}

    def add(self, host: str, relationship: str, evidence: str, confidence: str,
            source: str, ip: Optional[str] = None) -> None:
        host = (host or "").strip().lower().rstrip(".")
        host = host[2:] if host.startswith("*.") else host
        if not host or not self.is_valid(host):
            return
        reg = self.registered(host)
        if not reg or reg == self.root or reg == self.target or host == self.target:
            return
        item = self.items.setdefault(reg, {
            "domain": reg, "relationships": [], "relationship_labels": [], "evidence": [],
            "ips": [], "hosts_seen": [], "sources": [], "_conf": 0, "_hits": 0,
        })
        if relationship not in item["relationships"]:
            item["relationships"].append(relationship)
            item["relationship_labels"].append(RELATIONSHIP_LABELS.get(relationship, relationship))
        if evidence and evidence not in item["evidence"] and len(item["evidence"]) < 4:
            item["evidence"].append(evidence)
        if ip and ip not in item["ips"] and len(item["ips"]) < 6:
            item["ips"].append(ip)
        if host != reg and host not in item["hosts_seen"] and len(item["hosts_seen"]) < 6:
            item["hosts_seen"].append(host)
        if source not in item["sources"]:
            item["sources"].append(source)
        item["_conf"] = max(item["_conf"], CONF_RANK.get(confidence, 1))
        item["_hits"] += 1

    def finalize(self) -> List[Dict[str, Any]]:
        out = []
        for item in self.items.values():
            conf = item.pop("_conf")
            hits = item.pop("_hits")
            # Corroboration: independent pivots agreeing, or the same domain seen repeatedly in PTR data
            if item["relationships"] == ["as_operator"]:
                pass  # being the network provider says nothing about owning the target
            elif len(item["sources"]) >= 2:
                conf = min(3, conf + 1)
            elif hits >= 3 and item["sources"] and item["sources"][0].startswith("PTR"):
                conf = min(3, conf + 1)
            item["confidence"] = CONF_NAME[conf]
            item["primary_relationship"] = item["relationships"][0]
            item["observations"] = hits
            out.append(item)
        out.sort(key=lambda i: (-CONF_RANK[i["confidence"]], -len(i["sources"]), -i["observations"], i["domain"]))
        return out[:MAX_RESULTS]


class DomainRelationDiscovery:
    @classmethod
    def discover(
        cls,
        target: str,
        is_ip: bool,
        resolved_ips: List[str],
        dns_data: Dict[str, Any],
        whois_data: Dict[str, Any],
        net_info: Dict[str, Any],
        co_hosted_primary: List[str],
        primary_ip: Optional[str],
        sibling_domains: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        from app.analyzers.domain_analyzer import DomainAnalyzer
        from app.core.settings_store import settings_store

        started = time.time()
        deadline = started + _TOTAL_BUDGET_S
        net_info = net_info or {}
        whois_data = whois_data or {}
        dns_data = dns_data or {}

        root = "" if is_ip else DomainAnalyzer.get_registered_domain(target)
        cache_key = f"{target}|{','.join(sorted(resolved_ips or []))}"
        cached = _CACHE.get(cache_key)
        if cached and started - cached[0] < _CACHE_TTL:
            return cached[1]

        pivots: List[Dict[str, Any]] = []
        info: Dict[str, Any] = {
            "performed": True,
            "asn": None, "asn_holder": None, "network_name": net_info.get("network_name"),
            "owner_org": whois_data.get("registrant_org") if _usable_registrant(whois_data.get("registrant_org")) else None,
            "is_shared_infrastructure": False, "shared_reason": None,
            "asn_prefix_count": 0, "asn_prefixes": [], "spf_ip_ranges": [],
            "ips_examined": list(resolved_ips or []), "ptr_probes": 0, "elapsed_s": 0.0,
            "pivots": pivots,
        }

        if not settings_store.is_external_allowed("allow_threat_intel_lookups"):
            pivots.append({"name": "All passive pivots", "status": "blocked", "found": 0,
                           "detail": "External threat-intel lookups are disabled by admin policy."})
            result = {"related_domains": [], "ownership_pivots": info}
            return result

        collector = _Collector(
            target=target, root=root,
            registered=DomainAnalyzer.get_registered_domain,
            is_valid=DomainAnalyzer._is_valid_domain_string,
        )

        # ------------------------------------------------------------------ ASN / network facts
        asn = cls._normalize_asn(net_info.get("asn"))
        if not asn and primary_ip:
            ov = cls._ripe_prefix_overview(primary_ip)
            if ov:
                asn = ov.get("asn")
                if ov.get("holder") and not net_info.get("as_org"):
                    net_info["as_org"] = f"{asn} {ov['holder']}"
                if ov.get("prefix") and ov["prefix"] not in (net_info.get("cidrs") or []):
                    net_info.setdefault("cidrs", []).append(ov["prefix"])
        holder = _clean_as_holder(net_info.get("as_org")) or net_info.get("org") or net_info.get("isp") or ""
        info["asn"] = asn
        info["asn_holder"] = holder or None

        shared_kw = _is_shared_infra(" ".join(filter(None, [
            holder, net_info.get("org"), net_info.get("isp"), net_info.get("network_name"),
        ])))
        if shared_kw:
            info["is_shared_infrastructure"] = True
            info["shared_reason"] = (
                f"AS holder / network matches shared hosting, cloud or CDN provider ('{shared_kw}'). "
                "Neighbouring addresses belong to other customers, so ASN/netblock pivots were skipped."
            )

        # ------------------------------------------------------------------ DNS policy pivots (instant)
        cls._pivot_dns_records(dns_data, root, collector, info, pivots)

        # ------------------------------------------------------------------ same-IP: primary IP data we already have
        if primary_ip and co_hosted_primary:
            conf = "medium" if len(co_hosted_primary) <= 25 else "low"
            for h in co_hosted_primary:
                collector.add(h, "same_ip", f"Co-hosted on {primary_ip}" + (" (shared hosting)" if conf == "low" else ""),
                              conf, "Reverse IP", primary_ip)
            pivots.append({"name": f"Reverse IP ({primary_ip})", "status": "ok", "found": len(co_hosted_primary),
                           "detail": "shared hosting - lower confidence" if conf == "low" else ""})

        # ------------------------------------------------------------------ Phase 1: parallel network pivots
        tasks: Dict[str, Callable[[], Dict[str, Any]]] = {}
        if root:
            tasks["Certificate Transparency - SAN co-listing"] = lambda: cls._task_cert_sans(root, DomainAnalyzer)
        orgs: List[Tuple[str, str, str]] = []
        if info["owner_org"]:
            orgs.append((info["owner_org"], "high", "registrant"))
        if holder and not info["is_shared_infrastructure"] and _usable_registrant(holder) \
                and holder.lower() != (info["owner_org"] or "").lower():
            orgs.append((holder, "medium", "AS holder"))
        for org, conf, origin in orgs[:2]:
            tasks[f"Certificate Transparency - organization '{org}'"] = \
                (lambda o=org, c=conf, og=origin: cls._task_cert_org(o, c, og, root, DomainAnalyzer))
        for extra_ip in [i for i in (resolved_ips or []) if i != primary_ip][:2]:
            if cls._is_global_ipv4(extra_ip):
                tasks[f"Reverse IP ({extra_ip})"] = (lambda ip=extra_ip: cls._task_reverse_ip(ip))
        if asn and not info["is_shared_infrastructure"]:
            tasks[f"Announced prefixes of {asn}"] = lambda: cls._task_asn_prefixes(asn)

        phase1_results: Dict[str, Dict[str, Any]] = {}
        if tasks:
            ex = ThreadPoolExecutor(max_workers=min(8, len(tasks)))
            futs = {ex.submit(fn): name for name, fn in tasks.items()}
            done, not_done = wait(list(futs), timeout=min(_PHASE1_BUDGET_S, max(1.0, deadline - time.time())))
            for f in done:
                name = futs[f]
                try:
                    phase1_results[name] = f.result()
                except Exception as e:
                    phase1_results[name] = {"hits": [], "meta": {"status": "failed", "detail": str(e)[:120]}}
            for f in not_done:
                phase1_results[futs[f]] = {"hits": [], "meta": {"status": "timeout", "detail": "no response in time"}}
            ex.shutdown(wait=False, cancel_futures=True)

        asn_prefix_list: List[str] = []
        for name, res in phase1_results.items():
            meta = res.get("meta", {})
            hits = res.get("hits", [])
            for h in hits:
                collector.add(*h)
            if "prefixes" in res:
                asn_prefix_list = res["prefixes"]
            pivots.append({
                "name": name, "status": meta.get("status", "ok"),
                "found": len({h[0] for h in hits}), "detail": meta.get("detail", ""),
            })

        if asn_prefix_list:
            info["asn_prefix_count"] = len(asn_prefix_list)
            info["asn_prefixes"] = asn_prefix_list[:60]

        # ------------------------------------------------------------------ Phase 2: PTR sweeps (corporate network + ASN)
        if primary_ip and cls._is_global_ipv4(primary_ip):
            if info["is_shared_infrastructure"]:
                pivots.append({"name": "Corporate network PTR sweep", "status": "skipped", "found": 0,
                               "detail": "shared hosting / cloud network"})
                pivots.append({"name": "Autonomous System PTR sampling", "status": "skipped", "found": 0,
                               "detail": "shared hosting / cloud AS"})
            else:
                own_net, own_ips = cls._own_network_ips(primary_ip, net_info.get("cidrs") or [])
                asn_ips: List[str] = []
                if asn_prefix_list and len(asn_prefix_list) <= ASN_OVERLARGE_PREFIX_COUNT:
                    asn_ips = cls._asn_sample_ips(asn_prefix_list, own_net)
                elif asn_prefix_list:
                    pivots.append({"name": "Autonomous System PTR sampling", "status": "skipped", "found": 0,
                                   "detail": f"{len(asn_prefix_list)} announced prefixes - large carrier network"})

                probe_map: Dict[str, str] = {ip: "same_network" for ip in own_ips}
                for ip in asn_ips:
                    probe_map.setdefault(ip, "same_asn")
                probe_map.pop(primary_ip, None)

                ptrs = cls._ptr_sweep(list(probe_map), deadline)
                info["ptr_probes"] = len(probe_map)
                found_net, found_asn = set(), set()
                for ip, host in ptrs.items():
                    if _is_generic_ptr(host, ip):
                        continue
                    reg = DomainAnalyzer.get_registered_domain(host)
                    if _is_domain_suffix(reg, INFRA_PTR_DOMAINS):
                        continue
                    rel = probe_map.get(ip, "same_network")
                    conf = "medium"
                    if holder and _looks_like_as_operator(reg, holder):
                        rel, conf = "as_operator", "low"  # the network provider itself, not necessarily the owner
                    collector.add(host, rel, f"PTR {ip} -> {host}", conf, "PTR sweep", ip)
                    (found_net if rel == "same_network" else found_asn).add(reg)
                pivots.append({
                    "name": f"Corporate network PTR sweep ({own_net})" if own_net else "Corporate network PTR sweep",
                    "status": "ok" if own_ips else "skipped", "found": len(found_net),
                    "detail": f"{len(own_ips)} addresses probed",
                })
                if asn_ips:
                    pivots.append({"name": f"Autonomous System PTR sampling ({asn})", "status": "ok",
                                   "found": len(found_asn), "detail": f"{len(asn_ips)} addresses across other prefixes"})

        related = collector.finalize()
        # Subdomains/hosts already discovered by the analyzer under the same root are not "other" domains
        info["elapsed_s"] = round(time.time() - started, 1)
        result = {"related_domains": related, "ownership_pivots": info}
        _CACHE[cache_key] = (started, result)
        return result

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _normalize_asn(asn: Any) -> Optional[str]:
        if not asn:
            return None
        s = str(asn).strip().upper()
        m = re.match(r'^(?:AS)?(\d+)', s)
        return f"AS{m.group(1)}" if m else None

    @staticmethod
    def _is_global_ipv4(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return isinstance(a, ipaddress.IPv4Address) and a.is_global
        except ValueError:
            return False

    @classmethod
    def _ripe_prefix_overview(cls, ip: str) -> Optional[Dict[str, Any]]:
        try:
            with httpx.Client(timeout=4.0) as c:
                r = c.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ip})
            if r.status_code != 200:
                return None
            d = r.json().get("data", {})
            asns = d.get("asns") or []
            if not asns:
                return None
            return {"asn": f"AS{asns[0].get('asn')}", "holder": asns[0].get("holder"), "prefix": d.get("resource")}
        except Exception as e:
            logger.debug(f"RIPEstat prefix-overview note for {ip}: {e}")
            return None

    # ------------------------------------------------------------------ DNS-record pivots
    @classmethod
    def _pivot_dns_records(cls, dns: Dict[str, Any], root: str, collector: _Collector,
                           info: Dict[str, Any], pivots: List[Dict[str, Any]]) -> None:
        spf_found, ns_found, mx_found = set(), set(), set()
        registered = collector.registered

        for txt in dns.get("txt", []) or []:
            txt = txt.replace('"', '')
            if not txt.lower().lstrip().startswith("v=spf1"):
                continue
            for tok in txt.split():
                tl = tok.lower()
                dom = None
                if tl.startswith("include:"):
                    dom = tl[8:]
                elif tl.startswith("redirect="):
                    dom = tl[9:]
                elif tl.startswith(("a:", "mx:", "exists:")):
                    dom = tl.split(":", 1)[1]
                elif tl.startswith(("ip4:", "ip6:")):
                    rng = tl.split(":", 1)[1]
                    if rng not in info["spf_ip_ranges"]:
                        info["spf_ip_ranges"].append(rng)
                    continue
                if dom:
                    dom = dom.split("/")[0].strip("%{}")
                    if not dom or "%" in dom:
                        continue
                    reg = registered(dom)
                    if reg and reg != root and not _is_domain_suffix(reg, KNOWN_MAIL_PLATFORMS) \
                            and not _is_domain_suffix(dom, KNOWN_MAIL_PLATFORMS):
                        collector.add(dom, "spf_reference", f"Authorised in SPF record: {tok}", "medium", "DNS SPF")
                        spf_found.add(reg)

        for ns in dns.get("ns", []) or []:
            reg = registered(ns)
            if reg and reg != root and not _is_domain_suffix(ns, KNOWN_DNS_PROVIDERS) \
                    and not any(p in ns.lower() for p in ("awsdns-", "azure-dns", "ui-dns")):
                collector.add(ns, "custom_nameserver", f"Authoritative nameserver {ns}", "low", "DNS NS")
                ns_found.add(reg)

        for mx in dns.get("mx", []) or []:
            host = mx.get("host") if isinstance(mx, dict) else str(mx)
            reg = registered(host or "")
            if reg and reg != root and not _is_domain_suffix(host or "", KNOWN_MAIL_PLATFORMS):
                collector.add(host, "mx_infrastructure", f"MX host {host}", "low", "DNS MX")
                mx_found.add(reg)

        pivots.append({"name": "SPF policy references", "status": "ok", "found": len(spf_found),
                       "detail": f"{len(info['spf_ip_ranges'])} authorised IP ranges" if info["spf_ip_ranges"] else ""})
        pivots.append({"name": "Vanity nameservers", "status": "ok", "found": len(ns_found), "detail": ""})
        pivots.append({"name": "Self-hosted MX", "status": "ok", "found": len(mx_found), "detail": ""})

    # ------------------------------------------------------------------ network tasks (run in threads)
    @staticmethod
    def _issuer_short(issuer: str) -> str:
        m = re.search(r'\bO=([^,]+)', issuer or "") or re.search(r'\bCN=([^,]+)', issuer or "")
        return m.group(1).strip() if m else (issuer or "unknown CA")[:40]

    @classmethod
    def _crt_fetch(cls, params: Dict[str, str]) -> Tuple[Optional[List[Dict[str, Any]]], str]:
        err = ""
        for attempt, timeout in enumerate((9.0, 6.0)):  # crt.sh frequently answers 502/timeouts once
            try:
                with httpx.Client(timeout=timeout, follow_redirects=True,
                                  headers={"User-Agent": "FileSanitizer-DomainIntel/1.0"}) as c:
                    r = c.get("https://crt.sh/", params={**params, "output": "json"})
                if r.status_code == 200:
                    data = r.json()
                    return (data if isinstance(data, list) else []), ""
                err = f"crt.sh HTTP {r.status_code}"
            except Exception as e:
                err = f"crt.sh unavailable ({type(e).__name__})"
            time.sleep(0.5)
        return None, err

    @classmethod
    def _task_cert_sans(cls, root: str, DomainAnalyzer) -> Dict[str, Any]:
        entries, err = cls._crt_fetch({"q": root})
        if entries is None:
            return {"hits": [], "meta": {"status": "failed", "detail": err}}
        hits: List[tuple] = []
        seen_certs = set()
        multi_tenant = 0
        for e in entries[:1500]:
            cid = e.get("id") or e.get("min_cert_id")
            if cid in seen_certs:
                continue
            seen_certs.add(cid)
            cn = (e.get("common_name") or "").lower()
            names = {n.strip().lower().lstrip("*.") for n in (e.get("name_value") or "").split("\n") if n.strip()}
            names.add(cn.lstrip("*."))
            names = {n for n in names if n and DomainAnalyzer._is_valid_domain_string(n)}
            regs = {DomainAnalyzer.get_registered_domain(n) for n in names}
            if root not in regs:
                continue
            if len(regs) > 25 or "cloudflaressl" in cn or cn.startswith("sni"):
                multi_tenant += 1  # multi-tenant CDN certificate: unrelated customers share it
                continue
            issuer = cls._issuer_short(e.get("issuer_name", ""))
            for n in names:
                if DomainAnalyzer.get_registered_domain(n) != root:
                    hits.append((n, "shared_certificate",
                                 f"Co-listed with {root} in certificate #{cid} (issuer: {issuer})",
                                 "high", "Certificate Transparency", None))
        detail = f"{len(seen_certs)} certificates examined"
        if multi_tenant:
            detail += f", {multi_tenant} multi-tenant CDN certificates ignored"
        return {"hits": hits[:400], "meta": {"status": "ok", "detail": detail}}

    @classmethod
    def _task_cert_org(cls, org: str, confidence: str, origin: str, root: str, DomainAnalyzer) -> Dict[str, Any]:
        entries, err = cls._crt_fetch({"O": org})
        if entries is None:
            return {"hits": [], "meta": {"status": "failed", "detail": err}}
        hits: List[tuple] = []
        seen = set()
        for e in entries[:2000]:
            cid = e.get("id") or e.get("min_cert_id")
            names = {n.strip().lower().lstrip("*.") for n in (e.get("name_value") or "").split("\n") if n.strip()}
            for n in names:
                if not DomainAnalyzer._is_valid_domain_string(n):
                    continue
                reg = DomainAnalyzer.get_registered_domain(n)
                if reg == root or reg in seen:
                    continue
                seen.add(reg)
                hits.append((n, "cert_organization",
                             f"Certificate #{cid} issued to organization '{org}' ({origin})",
                             confidence, "Certificate Transparency", None))
        return {"hits": hits[:400], "meta": {"status": "ok", "detail": f"{len(entries)} certificates for '{org}'"}}

    @classmethod
    def _task_reverse_ip(cls, ip: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=4.0) as c:
                r = c.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip})
            text = r.text.strip()
            low = text.lower()
            if r.status_code != 200 or low.startswith("error") or "api count exceeded" in low or "no records" in low:
                return {"hits": [], "meta": {"status": "failed" if r.status_code != 200 or "exceeded" in low else "ok",
                                             "detail": "no records / rate limited"}}
            names = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
            conf = "medium" if len(names) <= 25 else "low"
            hits = [(n, "same_ip", f"Co-hosted on {ip}" + (" (shared hosting)" if conf == "low" else ""),
                     conf, "Reverse IP", ip) for n in names]
            return {"hits": hits, "meta": {"status": "ok", "detail": f"{len(names)} hosts"}}
        except Exception as e:
            return {"hits": [], "meta": {"status": "failed", "detail": f"reverse-IP unavailable ({type(e).__name__})"}}

    @classmethod
    def _task_asn_prefixes(cls, asn: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=9.0) as c:
                r = c.get("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": asn})
            if r.status_code != 200:
                return {"hits": [], "meta": {"status": "failed", "detail": f"RIPEstat HTTP {r.status_code}"}, "prefixes": []}
            prefixes = [p.get("prefix") for p in r.json().get("data", {}).get("prefixes", []) if p.get("prefix")]
            prefixes.sort(key=lambda x: (":" in x, x))  # IPv4 first
            return {"hits": [], "meta": {"status": "ok", "detail": f"{len(prefixes)} prefixes announced"},
                    "prefixes": prefixes}
        except Exception as e:
            return {"hits": [], "meta": {"status": "failed", "detail": f"RIPEstat unavailable ({type(e).__name__})"},
                    "prefixes": []}

    # ------------------------------------------------------------------ PTR sweeps
    @classmethod
    def _own_network_ips(cls, ip: str, cidrs: List[str]) -> Tuple[Optional[str], List[str]]:
        """Addresses to probe in the network block the target IP is allocated in."""
        addr = ipaddress.ip_address(ip)
        containing = []
        for c in cidrs:
            try:
                n = ipaddress.ip_network(c, strict=False)
                if isinstance(n, ipaddress.IPv4Network) and addr in n:
                    containing.append(n)
            except ValueError:
                continue
        net = max(containing, key=lambda n: n.prefixlen) if containing else ipaddress.ip_network(f"{ip}/24", strict=False)
        ips: List[str] = []
        if net.num_addresses <= 1024:
            ips = _sample_hosts(net, 512)
        else:
            local24 = ipaddress.ip_network(f"{ip}/24", strict=False)
            ips = _sample_hosts(local24, 254)
            ips += [i for i in _sample_hosts(net, 128) if i not in ips]
        return str(net), ips

    @classmethod
    def _asn_sample_ips(cls, prefixes: List[str], own_net: Optional[str]) -> List[str]:
        nets = _to_ipv4_networks(prefixes)
        own = ipaddress.ip_network(own_net, strict=False) if own_net else None
        cand = [n for n in nets if not (own and (n.overlaps(own))) and 16 <= n.prefixlen <= 24]
        cand.sort(key=lambda n: -n.prefixlen)  # smaller blocks first: more likely corporate server ranges
        ips: List[str] = []
        for n in cand[:8]:
            ips.extend(_sample_hosts(n, 16))
        return ips

    @classmethod
    def _ptr_sweep(cls, ips: List[str], deadline: float) -> Dict[str, str]:
        if not ips:
            return {}

        def _ptr(ip: str) -> Optional[str]:
            try:
                return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
            except Exception:
                return None

        results: Dict[str, str] = {}
        ex = ThreadPoolExecutor(max_workers=64)
        futs = {ex.submit(_ptr, ip): ip for ip in ips}
        done, _ = wait(list(futs), timeout=max(2.0, deadline - time.time()))
        for f in done:
            try:
                host = f.result()
            except Exception:
                host = None
            if host:
                results[futs[f]] = host
        ex.shutdown(wait=False, cancel_futures=True)
        return results
