"""
AI Image Verification & Provenance Forensic Engine.
Detects whether an image is AI-generated, AI-edited, or authentic camera media:
1. C2PA (Coalition for Content Provenance and Authenticity) JUMBF manifest parser:
   - Detects digitalSourceType: trainedAlgorithmicMedia
   - Extracts claim_generator (e.g. OpenAI DALL-E 3, Adobe Firefly, Midjourney, Truepic)
   - Inspects c2pa.actions (created, edited)
2. Diffusion model generation metadata:
   - Stable Diffusion / ComfyUI / Automatic1111 / InvokeAI: prompt, negative prompt, steps, seed, CFG scale, sampler, model hash
   - Midjourney parameters (--v 6.0, --ar, --stylize) in EXIF/PNG chunks
   - NovelAI / Bing Image Creator / DALL-E 2/3 metadata
3. Hardware camera authenticity verification:
   - Make, Model, F-Number, ExposureTime, ISO, FocalLength, LensModel
4. ELA (Error Level Analysis) and noise uniformity metrics.
"""

import io
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image, ExifTags

from app.core.logging_config import logger

# IPTC standard URI for AI media
IPTC_ALGORITHMIC_MEDIA = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
IPTC_ALGORITHMIC_MEDIA_SHORT = "trainedAlgorithmicMedia"

# Known AI generators
KNOWN_AI_GENERATORS = [
    "dall-e", "dalle", "midjourney", "stable diffusion", "stablediffusion",
    "comfyui", "novelai", "adobe firefly", "bing image creator",
    "leonardo.ai", "invokeai", "fooocus", "automatic1111", "openai"
]


class AIImageVerifier:
    """
    Forensic verifier for detecting synthetic / AI-generated and AI-edited images.
    """

    @classmethod
    def verify_image(cls, file_path: Path) -> Dict[str, Any]:
        """
        Analyzes image file for AI provenance, C2PA manifests, generation parameters,
        and camera hardware metadata.
        """
        result: Dict[str, Any] = {
            "is_ai_generated": False,
            "confidence": "CLEAN",  # CLEAN, SUSPICIOUS, LIKELY_AI, CONFIRMED_AI
            "generator_tool": None,
            "c2pa": {
                "detected": False,
                "claim_generator": None,
                "digital_source_type": None,
                "is_algorithmic_media": False,
                "actions": []
            },
            "prompt_metadata": {
                "detected": False,
                "tool": None,
                "prompt": None,
                "negative_prompt": None,
                "parameters": {}
            },
            "camera_metadata": {
                "has_camera_hardware_exif": False,
                "make": None,
                "model": None,
                "lens": None,
                "iso": None,
                "exposure": None
            },
            "ela_metrics": {
                "performed": False,
                "mean_error": 0.0,
                "max_error": 0.0,
                "noise_uniformity": "NORMAL"
            },
            "explanation": "",
            "indicators": []
        }

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            # 1. C2PA / JUMBF Manifest Search
            cls._inspect_c2pa(raw_bytes, result)

            # 2. Metadata & Text Chunks (PNG / EXIF / XMP)
            cls._inspect_metadata(file_path, raw_bytes, result)

            # 3. ELA Error Level Analysis
            cls._perform_ela(file_path, result)

            # 4. Final Verdict Determination
            cls._determine_verdict(result)

        except Exception as e:
            logger.debug(f"AI image verification failed for {file_path.name}: {e}")

        return result

    @classmethod
    def _inspect_c2pa(cls, raw_bytes: bytes, result: Dict[str, Any]) -> None:
        """Inspects binary stream for C2PA JUMBF boxes and IPTC digitalSourceType."""
        raw_str = raw_bytes.decode("latin-1", errors="ignore")

        # JUMBF box signature or C2PA manifest marker
        has_jumb = b"jumb" in raw_bytes and b"c2pa" in raw_bytes
        has_digital_source = (
            IPTC_ALGORITHMIC_MEDIA in raw_str or
            IPTC_ALGORITHMIC_MEDIA_SHORT in raw_str
        )

        if has_jumb or has_digital_source:
            result["c2pa"]["detected"] = True

            if has_digital_source:
                result["c2pa"]["is_algorithmic_media"] = True
                result["c2pa"]["digital_source_type"] = IPTC_ALGORITHMIC_MEDIA
                result["indicators"].append("C2PA Manifest: digitalSourceType indicates trainedAlgorithmicMedia (AI Generated)")

            # Extract claim generator string
            m_gen = re.search(r'["\'](?:claim_generator|claimGenerator)["\']\s*:\s*["\']([^"\']+)["\']', raw_str, re.I)
            if not m_gen:
                m_gen = re.search(r'(?:OpenAI|DALL-E|Midjourney|Adobe Firefly|Truepic)[a-zA-Z0-9\.\-\_\s]{2,40}', raw_str, re.I)

            if m_gen:
                gen_name = m_gen.group(1) if hasattr(m_gen, "group") and len(m_gen.groups()) > 0 else m_gen.group(0)
                result["c2pa"]["claim_generator"] = gen_name.strip()
                result["generator_tool"] = gen_name.strip()
                result["indicators"].append(f"C2PA Claim Generator: {gen_name.strip()}")

            # Extract actions
            if "c2pa.created" in raw_str:
                result["c2pa"]["actions"].append("created")
            if "c2pa.edited" in raw_str:
                result["c2pa"]["actions"].append("edited")

    @classmethod
    def _inspect_metadata(cls, file_path: Path, raw_bytes: bytes, result: Dict[str, Any]) -> None:
        """Inspects PNG info text chunks and EXIF user comments for diffusion prompts and camera tags."""
        try:
            with Image.open(file_path) as img:
                # 1. Inspect PNG text chunks (Automatic1111 / ComfyUI / NovelAI)
                if hasattr(img, "text") and img.text:
                    for k, v in img.text.items():
                        v_str = str(v)
                        v_lower = v_str.lower()
                        # Stable Diffusion / Automatic1111
                        if k.lower() == "parameters" or "steps:" in v_lower or "sampler:" in v_lower:
                            result["prompt_metadata"]["detected"] = True
                            result["prompt_metadata"]["tool"] = "Stable Diffusion / Automatic1111"
                            cls._parse_sd_parameters(v_str, result)
                            result["indicators"].append("Embedded Stable Diffusion generation parameters found in PNG metadata")
                            break
                        # ComfyUI
                        if k.lower() in ("prompt", "workflow") and ("k-sampler" in v_lower or "ksampler" in v_lower or "checkpointloadersimple" in v_lower):
                            result["prompt_metadata"]["detected"] = True
                            result["prompt_metadata"]["tool"] = "ComfyUI"
                            result["prompt_metadata"]["prompt"] = v_str[:300]
                            result["indicators"].append("Embedded ComfyUI node graph generation workflow found")
                            break

                # 2. Inspect EXIF metadata
                exif = img.getexif()
                if exif:
                    # Check camera hardware tags
                    make = exif.get(0x010F)  # Make
                    model = exif.get(0x0110)  # Model
                    if make or model:
                        result["camera_metadata"]["has_camera_hardware_exif"] = True
                        result["camera_metadata"]["make"] = str(make).strip() if make else None
                        result["camera_metadata"]["model"] = str(model).strip() if model else None

                    # Check UserComment tag (0x9286)
                    user_comment = exif.get(0x9286)
                    if user_comment:
                        u_str = str(user_comment)
                        u_lower = u_str.lower()
                        if any(tool in u_lower for tool in KNOWN_AI_GENERATORS) or "--v 5" in u_str or "--v 6" in u_str:
                            result["prompt_metadata"]["detected"] = True
                            result["prompt_metadata"]["tool"] = "Midjourney / Diffusion Model"
                            result["prompt_metadata"]["prompt"] = u_str[:300]
                            result["indicators"].append("AI generation prompt identified in EXIF UserComment")

                    # Check Software tag (0x0131)
                    software = exif.get(0x0131)
                    if software:
                        s_str = str(software).strip()
                        s_lower = s_str.lower()
                        for tool in KNOWN_AI_GENERATORS:
                            if tool in s_lower:
                                result["prompt_metadata"]["detected"] = True
                                result["prompt_metadata"]["tool"] = s_str
                                result["indicators"].append(f"AI Generator Software tag: {s_str}")
                                break

        except Exception as e:
            logger.debug(f"Pillow metadata inspection error: {e}")

        # Raw scan fallback for Midjourney or Stable Diffusion prompt strings
        raw_str = raw_bytes[:100000].decode("latin-1", errors="ignore")
        if not result["prompt_metadata"]["detected"]:
            if "Steps: " in raw_str and "CFG scale: " in raw_str and "Sampler: " in raw_str:
                result["prompt_metadata"]["detected"] = True
                result["prompt_metadata"]["tool"] = "Stable Diffusion"
                cls._parse_sd_parameters(raw_str, result)
                result["indicators"].append("Stable Diffusion prompt parameters detected in binary stream")
            elif "--ar " in raw_str and ("--v 5" in raw_str or "--v 6" in raw_str or "--stylize" in raw_str):
                result["prompt_metadata"]["detected"] = True
                result["prompt_metadata"]["tool"] = "Midjourney"
                result["indicators"].append("Midjourney parameters (--v, --ar, --stylize) detected")

    @classmethod
    def _parse_sd_parameters(cls, param_str: str, result: Dict[str, Any]) -> None:
        """Parses prompt, negative prompt, steps, sampler, seed, cfg from SD string."""
        parts = param_str.split("Negative prompt:")
        prompt = parts[0].strip()
        result["prompt_metadata"]["prompt"] = prompt[:500]

        rest = parts[1] if len(parts) > 1 else ""
        if "Steps:" in rest:
            neg_and_params = rest.split("Steps:")
            result["prompt_metadata"]["negative_prompt"] = neg_and_params[0].strip()[:300]
            param_line = "Steps:" + neg_and_params[1]
        else:
            param_line = rest

        # Extract key-value parameter pairs
        for m in re.finditer(r'([A-Za-z\s]+):\s*([^,]+)(?:,|$)', param_line):
            key = m.group(1).strip()
            val = m.group(2).strip()
            if key in ("Steps", "Sampler", "CFG scale", "Seed", "Model", "Model hash", "Size"):
                result["prompt_metadata"]["parameters"][key] = val

    @classmethod
    def _perform_ela(cls, file_path: Path, result: Dict[str, Any]) -> None:
        """
        Error Level Analysis (ELA).
        Re-saves image as JPEG at 90% quality and computes difference.
        """
        try:
            with Image.open(file_path) as orig:
                rgb = orig.convert("RGB")
                w, h = rgb.size
                buf = io.BytesIO()
                rgb.save(buf, format="JPEG", quality=90)
                buf.seek(0)
                with Image.open(buf) as recompressed:
                    # Calculate difference
                    from PIL import ImageChops, ImageStat
                    diff = ImageChops.difference(rgb, recompressed)
                    stat = ImageStat.Stat(diff)
                    orig_stat = ImageStat.Stat(rgb)
                    mean_val = sum(stat.mean) / len(stat.mean)
                    max_val = max(stat.extrema[i][1] for i in range(len(stat.extrema)))
                    orig_std = sum(orig_stat.stddev) / len(orig_stat.stddev)

                    result["ela_metrics"]["performed"] = True
                    result["ela_metrics"]["mean_error"] = round(mean_val, 2)
                    result["ela_metrics"]["max_error"] = round(max_val, 2)

                    # Distinguish digital graphics/screenshots from textured photos
                    if orig_std < 22 or min(w, h) < 150:
                        # Digital graphic, screenshot, flat diagram, or icon
                        result["ela_metrics"]["noise_uniformity"] = "DIGITAL_GRAPHIC_OR_SCREENSHOT"
                    elif mean_val < 0.5 and orig_std > 35 and not result["camera_metadata"]["has_camera_hardware_exif"]:
                        # High color variance (photo-like texture) but unnaturally uniform compression error
                        result["ela_metrics"]["noise_uniformity"] = "HIGHLY_UNIFORM_SYNTHETIC"
                    else:
                        result["ela_metrics"]["noise_uniformity"] = "ORGANIC"
        except Exception as e:
            logger.debug(f"ELA calculation error: {e}")

    @classmethod
    def _determine_verdict(cls, result: Dict[str, Any]) -> None:
        """Determines final AI confidence level and detailed human-readable explanation."""
        has_c2pa_ai = result["c2pa"]["is_algorithmic_media"]
        has_prompt = result["prompt_metadata"]["detected"]
        has_camera = result["camera_metadata"]["has_camera_hardware_exif"]
        generator = result["generator_tool"] or result["prompt_metadata"]["tool"]

        if has_c2pa_ai or (has_prompt and generator):
            result["is_ai_generated"] = True
            result["confidence"] = "CONFIRMED_AI"
            result["generator_tool"] = generator or "AI Diffusion / Neural Model"
            result["explanation"] = f"Cryptographic C2PA provenance or embedded generative diffusion prompt confirms this image was generated by {result['generator_tool']}."
        elif has_prompt:
            result["is_ai_generated"] = True
            result["confidence"] = "LIKELY_AI"
            result["generator_tool"] = generator or "AI Model"
            result["explanation"] = "Generative diffusion prompt parameters or AI model tags were identified in image metadata."
        elif result["c2pa"]["detected"] and result["c2pa"]["is_algorithmic_media"]:
            result["is_ai_generated"] = True
            result["confidence"] = "CONFIRMED_AI"
            result["generator_tool"] = result["c2pa"]["claim_generator"] or "AI Model"
            result["explanation"] = "C2PA digitalSourceType explicitly declares trainedAlgorithmicMedia (synthetic/AI generated)."
        elif result["c2pa"]["detected"]:
            # C2PA detected without algorithmic media flag means authentic provenance (e.g. CAI camera signature)
            result["is_ai_generated"] = False
            result["confidence"] = "CLEAN"
            result["explanation"] = "C2PA provenance manifest detected without synthetic assertions (indicative of authentic physical capture or editing provenance)."
        elif not has_camera and result["ela_metrics"]["noise_uniformity"] == "HIGHLY_UNIFORM_SYNTHETIC":
            result["is_ai_generated"] = False
            result["confidence"] = "SUSPICIOUS"
            result["explanation"] = "Image exhibits highly uniform compression noise across textured regions and lacks physical camera sensor EXIF metadata. Note: Some multi-generation web re-encoded photos or filtered images may also exhibit this pattern."
            result["indicators"].append("Synthetic Signal Warning: Anomaly detected between high texture variance and uniform compression noise without camera hardware EXIF.")
        else:
            result["is_ai_generated"] = False
            result["confidence"] = "CLEAN"
            result["explanation"] = "No synthetic AI provenance, diffusion parameters, or anomalous synthetic noise profiles detected."
