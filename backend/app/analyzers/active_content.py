import re
from pathlib import Path
from typing import Dict, Any, List, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from bs4 import BeautifulSoup
import defusedxml.minidom as safe_minidom

URL_REGEX = re.compile(
    r'(?:https?|ftp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+',
    re.IGNORECASE
)

# Common HTML/SVG inline event handler attributes
EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onmouseout", "onmouseenter",
    "onfocus", "onblur", "onchange", "onsubmit", "onreset", "onkeydown",
    "onkeypress", "onkeyup", "onanimationstart", "onanimationend"
]

class ActiveContentAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "ActiveContentAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {
            "has_javascript": False,
            "scripts_count": 0,
            "has_event_handlers": False,
            "event_handlers_found": [],
            "has_external_resources": False,
            "external_resources": [],
            "has_iframes": False,
            "has_forms": False,
            "has_redirects": False,
            "has_embedded_objects": False,
            "urls": []
        }

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to read file: {e}",
                findings=[],
                data={}
            )

        # Extract all raw URLs
        for u in URL_REGEX.findall(content):
            urls.add(u)

        is_svg = (mime_type == "image/svg+xml" or filename.lower().endswith(".svg") or "<svg" in content.lower())

        if is_svg:
            # SVG active content inspection
            try:
                # Safe XML parsing (prevents XXE / entity bombs)
                dom = safe_minidom.parseString(content)

                # 1. Script elements
                scripts = dom.getElementsByTagName("script")
                if scripts:
                    data["has_javascript"] = True
                    data["scripts_count"] = len(scripts)
                    findings.append(Finding(
                        category="javascript",
                        severity="high",
                        title="JavaScript Detected in SVG",
                        description=f"SVG contains {len(scripts)} executable <script> element(s). SVGs can execute arbitrary JavaScript in browsers.",
                        details={"script_tags": len(scripts)}
                    ))

                # 2. Walk elements for event handlers and javascript: URLs
                for elem in dom.getElementsByTagName("*"):
                    # Check event handler attributes
                    for attr in EVENT_HANDLERS:
                        if elem.hasAttribute(attr):
                            data["has_event_handlers"] = True
                            data["event_handlers_found"].append(f"{elem.tagName}[{attr}]")

                    # Check href / xlink:href for javascript: URIs
                    for href_attr in ["href", "xlink:href"]:
                        if elem.hasAttribute(href_attr):
                            val = elem.getAttribute(href_attr).strip()
                            if val.lower().startswith("javascript:"):
                                data["has_javascript"] = True
                                findings.append(Finding(
                                    category="javascript",
                                    severity="high",
                                    title=f"JavaScript Pseudo-Protocol Found in {elem.tagName}",
                                    description=f"Attribute '{href_attr}' contains executable 'javascript:' payload."
                                ))
                            elif val.startswith("http://") or val.startswith("https://"):
                                data["has_external_resources"] = True
                                data["external_resources"].append(val)
                                urls.add(val)

                if data["has_event_handlers"]:
                    findings.append(Finding(
                        category="javascript",
                        severity="high",
                        title=f"Inline Event Handlers Detected in SVG ({len(data['event_handlers_found'])})",
                        description="SVG contains DOM event handler attributes that execute script on render or interaction.",
                        details={"handlers": data["event_handlers_found"][:10]}
                    ))

                if data["has_external_resources"]:
                    findings.append(Finding(
                        category="url",
                        severity="medium",
                        title=f"External Resources Referenced in SVG ({len(data['external_resources'])})",
                        description="SVG loads images, stylesheets, or references from external servers.",
                        details={"resources": data["external_resources"][:10]}
                    ))

            except Exception as e:
                # Malformed XML or parser issue
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="SVG Parsing Warning",
                    description=f"XML parser encountered syntax anomaly: {e}"
                ))

        else:
            # HTML content inspection
            try:
                soup = BeautifulSoup(content, "html.parser")

                # 1. Scripts
                scripts = soup.find_all("script")
                if scripts:
                    data["has_javascript"] = True
                    data["scripts_count"] = len(scripts)
                    findings.append(Finding(
                        category="javascript",
                        severity="high",
                        title=f"JavaScript Code Detected in HTML ({len(scripts)} tags)",
                        description="Document contains script tags. Active execution poses XSS and client-side exploit risks."
                    ))

                # 2. Iframes
                iframes = soup.find_all("iframe")
                if iframes:
                    data["has_iframes"] = True
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title=f"Embedded Iframes Detected ({len(iframes)})",
                        description="HTML embeds external pages via iframes, commonly used for clickjacking or phishing.",
                        details={"count": len(iframes)}
                    ))

                # 3. Forms
                forms = soup.find_all("form")
                if forms:
                    data["has_forms"] = True
                    findings.append(Finding(
                        category="structure",
                        severity="medium",
                        title=f"Interactive Form Elements Detected ({len(forms)})",
                        description="HTML contains forms capable of credential harvesting or data exfiltration.",
                        details={"count": len(forms)}
                    ))

                # 4. Embedded objects
                objects = soup.find_all(["object", "embed", "applet"])
                if objects:
                    data["has_embedded_objects"] = True
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title=f"Embedded Binary Objects in HTML ({len(objects)})",
                        description="HTML contains legacy or binary plugin object tags (<object>, <embed>)."
                    ))

                # 5. Meta refresh redirects
                for meta in soup.find_all("meta"):
                    if meta.get("http-equiv", "").lower() == "refresh":
                        data["has_redirects"] = True
                        findings.append(Finding(
                            category="url",
                            severity="medium",
                            title="Automatic HTTP-EQUIV Refresh / Redirect Found",
                            description="HTML forces an automated redirect to another location upon opening."
                        ))

                # 6. Event handlers in any tag
                for tag in soup.find_all(True):
                    for attr in tag.attrs:
                        if attr.lower() in EVENT_HANDLERS or attr.lower().startswith("on"):
                            data["has_event_handlers"] = True
                            data["event_handlers_found"].append(f"{tag.name}[{attr}]")

                if data["has_event_handlers"]:
                    findings.append(Finding(
                        category="javascript",
                        severity="high",
                        title=f"Inline Event Handlers Detected in HTML ({len(data['event_handlers_found'])})",
                        description="HTML uses DOM event handlers (e.g. onload, onclick).",
                        details={"handlers": data["event_handlers_found"][:10]}
                    ))

            except Exception as e:
                logger.debug(f"Error parsing HTML: {e}")

        data["urls"] = list(urls)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
