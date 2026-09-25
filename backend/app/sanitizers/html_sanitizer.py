from pathlib import Path
from typing import List
from bs4 import BeautifulSoup
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onmouseout", "onmouseenter",
    "onfocus", "onblur", "onchange", "onsubmit", "onreset", "onkeydown",
    "onkeypress", "onkeyup"
]

class HTMLSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "HTMLSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        removed_items: List[str] = []
        warnings: List[str] = []

        try:
            content = input_path.read_text(encoding="utf-8", errors="replace")
            soup = BeautifulSoup(content, "html.parser")

            # 1. Strip <script> tags
            scripts = soup.find_all("script")
            for s in scripts:
                s.decompose()
            if scripts:
                removed_items.append(f"Purged {len(scripts)} executable <script> block(s)")

            # 2. Strip <iframe>, <object>, <embed>, <applet>
            dangerous_tags = soup.find_all(["iframe", "object", "embed", "applet"])
            for t in dangerous_tags:
                t.decompose()
            if dangerous_tags:
                removed_items.append(f"Purged {len(dangerous_tags)} dangerous embedded object/iframe tag(s)")

            # 3. Strip <form> tags
            forms = soup.find_all("form")
            for f in forms:
                f.unwrap()
            if forms:
                removed_items.append(f"Neutralized {len(forms)} HTML form(s)")

            # 4. Strip meta refresh
            metas = soup.find_all("meta")
            for m in metas:
                if m.get("http-equiv", "").lower() == "refresh":
                    m.decompose()
                    removed_items.append("Removed automatic meta-refresh redirect")

            # 5. Strip all inline on* event handlers and javascript: URLs
            removed_events = 0
            for tag in soup.find_all(True):
                for attr in list(tag.attrs.keys()):
                    if attr.lower() in EVENT_HANDLERS or attr.lower().startswith("on"):
                        del tag[attr]
                        removed_events += 1
                    elif attr.lower() in ["href", "src"]:
                        val = str(tag[attr]).strip().lower()
                        if val.startswith("javascript:"):
                            del tag[attr]
                            removed_items.append(f"Stripped 'javascript:' pseudo-protocol from <{tag.name}>")
                        elif (val.startswith("http://") or val.startswith("https://")) and options.remove_external_links:
                            del tag[attr]

            if removed_events > 0:
                removed_items.append(f"Removed {removed_events} inline DOM event listener(s)")

            # 6. Remove hyperlinks if requested
            if options.remove_hyperlinks or options.remove_external_links:
                for a in soup.find_all("a"):
                    if a.has_attr("href"):
                        del a["href"]
                removed_items.append("Removed hyperlinks from document")

            output_path.parent.mkdir(parents=True, exist_ok=True)
            clean_html = str(soup)
            output_path.write_text(clean_html, encoding="utf-8")

            base_name = original_filename.rsplit(".", 1)[0]
            clean_filename = f"{base_name}_sanitized.html"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension="html",
                removed_items=removed_items,
                warnings=warnings
            )

        except Exception as e:
            logger.error(f"HTML sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="html",
                warnings=[f"HTML sanitization error: {e}"]
            )
