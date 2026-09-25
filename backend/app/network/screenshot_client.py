from pathlib import Path
from typing import Optional
import httpx
from app.config import settings
from app.network.ssrf import validate_url_for_ssrf
from app.core.logging_config import logger

class ScreenshotClient:
    """
    Communicates with the isolated sandboxed browser container
    to capture website screenshots with strict SSRF pre-validation.
    """

    @classmethod
    def capture_screenshot(cls, url: str, output_path: Path) -> bool:
        if not settings.SCREENSHOT_ENABLED:
            return False

        # 1. Enforce strict SSRF check before requesting browser navigation
        is_safe, reason, _ = validate_url_for_ssrf(url)
        if not is_safe:
            logger.warning(f"Screenshot blocked by SSRF protection for {url}: {reason}")
            return False

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with httpx.Client(timeout=settings.SCREENSHOT_TIMEOUT) as client:
                resp = client.post(
                    settings.BROWSER_SERVICE_URL,
                    json={"url": url},
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    output_path.write_bytes(resp.content)
                    logger.info(f"Captured screenshot for {url} -> {output_path.name}")
                    return True
                else:
                    logger.debug(f"Browser service returned status {resp.status_code} for {url}")
                    return False
        except Exception as e:
            logger.debug(f"Browser screenshot service unavailable ({e}) for {url}")
            return False
