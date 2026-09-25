from typing import Dict, Any, List
from pydantic import BaseModel, Field

class MetadataField(BaseModel):
    name: str
    value: str
    is_sensitive: bool = False
    category: str = "general"  # general, document, location, camera, embedded

class StructuredMetadata(BaseModel):
    general: List[MetadataField] = Field(default_factory=list)
    document: List[MetadataField] = Field(default_factory=list)
    location: List[MetadataField] = Field(default_factory=list)
    camera: List[MetadataField] = Field(default_factory=list)
    embedded: List[MetadataField] = Field(default_factory=list)
    total_fields: int = 0
    sensitive_count: int = 0

class MetadataExtractor:
    @classmethod
    def consolidate(
        cls,
        filename: str,
        file_size: int,
        mime_type: str,
        hashes: Dict[str, str],
        analysis_data: Dict[str, Any]
    ) -> StructuredMetadata:
        general: List[MetadataField] = []
        document: List[MetadataField] = []
        location: List[MetadataField] = []
        camera: List[MetadataField] = []
        embedded: List[MetadataField] = []

        # 1. General
        general.append(MetadataField(name="Filename", value=filename, category="general"))
        general.append(MetadataField(name="File Size", value=f"{file_size:,} bytes", category="general"))
        general.append(MetadataField(name="MIME Type", value=mime_type, category="general"))
        general.append(MetadataField(name="SHA-256", value=hashes.get("sha256", "N/A"), category="general"))
        general.append(MetadataField(name="MD5", value=hashes.get("md5", "N/A"), category="general"))

        # 2. Location (GPS)
        image_data = analysis_data.get("image", {})
        if image_data.get("has_gps") and image_data.get("gps_coordinates"):
            coords = image_data["gps_coordinates"]
            location.append(MetadataField(
                name="GPS Coordinates",
                value=coords.get("readable", "Present"),
                is_sensitive=True,
                category="location"
            ))
            location.append(MetadataField(
                name="Latitude",
                value=str(coords.get("latitude", "")),
                is_sensitive=True,
                category="location"
            ))
            location.append(MetadataField(
                name="Longitude",
                value=str(coords.get("longitude", "")),
                is_sensitive=True,
                category="location"
            ))

        # 3. Document / Author
        doc_meta = {}
        pdf_data = analysis_data.get("pdf", {})
        if pdf_data.get("metadata"):
            doc_meta.update(pdf_data["metadata"])

        office_data = analysis_data.get("office", {})
        if office_data.get("metadata"):
            doc_meta.update(office_data["metadata"])

        if image_data.get("author_info"):
            doc_meta.update(image_data["author_info"])

        for k, v in doc_meta.items():
            if v and str(v).strip():
                k_lower = k.lower()
                has_url = "http://" in str(v) or "https://" in str(v)
                is_sens = any(term in k_lower for term in ["author", "creator", "modifier", "lastmodified", "producer"]) or has_url
                document.append(MetadataField(
                    name=k.capitalize(),
                    value=str(v),
                    is_sensitive=is_sens,
                    category="document"
                ))

        # 4. Camera Hardware / Software
        cam_info = image_data.get("camera_info", {})
        for k, v in cam_info.items():
            is_sens = (k in ["BodySerialNumber", "Software"])
            camera.append(MetadataField(
                name=k,
                value=str(v),
                is_sensitive=is_sens,
                category="camera"
            ))

        # 5. Embedded Content Summary
        urls = analysis_data.get("urls", [])
        embedded.append(MetadataField(
            name="External URLs",
            value=f"{len(urls)} discovered",
            is_sensitive=(len(urls) > 0),
            category="embedded"
        ))

        has_js = (
            pdf_data.get("has_javascript") or
            analysis_data.get("active_content", {}).get("has_javascript")
        )
        embedded.append(MetadataField(
            name="JavaScript",
            value="DETECTED" if has_js else "NO",
            is_sensitive=bool(has_js),
            category="embedded"
        ))

        has_macros = office_data.get("has_macros", False)
        embedded.append(MetadataField(
            name="VBA Macros",
            value="DETECTED" if has_macros else "NO",
            is_sensitive=bool(has_macros),
            category="embedded"
        ))

        has_att = (
            pdf_data.get("has_embedded_files") or
            office_data.get("has_embedded_files") or
            office_data.get("has_ole_objects")
        )
        att_count = len(pdf_data.get("embedded_files", [])) + len(office_data.get("ole_objects", []))
        embedded.append(MetadataField(
            name="Attachments / OLE Objects",
            value=f"{att_count} found" if has_att else "0",
            is_sensitive=bool(has_att),
            category="embedded"
        ))

        all_fields = general + document + location + camera + embedded
        total = len(all_fields)
        sens = sum(1 for f in all_fields if f.is_sensitive)

        return StructuredMetadata(
            general=general,
            document=document,
            location=location,
            camera=camera,
            embedded=embedded,
            total_fields=total,
            sensitive_count=sens
        )
