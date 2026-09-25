from app.sanitizers.base import SanitizationOptions

PROFILES = {
    "minimal": SanitizationOptions(
        profile="minimal",
        remove_metadata=True,
        remove_gps=True,
        remove_author=True,
        remove_timestamps=False,
        remove_comments=False,
        remove_embedded_files=False,
        remove_macros=False,
        remove_javascript=False,
        remove_external_links=False,
        remove_hyperlinks=False,
        reencode_image=False,
        flatten_image=False,
        flatten_document=False,
        rasterize_pages=False,
        strip_active_content=False,
        strip_external_resources=False
    ),
    "privacy": SanitizationOptions(
        profile="privacy",
        remove_metadata=True,
        remove_gps=True,
        remove_author=True,
        remove_timestamps=True,
        remove_comments=True,
        remove_embedded_files=False,
        remove_macros=False,
        remove_javascript=False,
        remove_external_links=False,
        remove_hyperlinks=False,
        reencode_image=True,
        flatten_image=False,
        flatten_document=False,
        rasterize_pages=False,
        strip_active_content=False,
        strip_external_resources=False
    ),
    "security": SanitizationOptions(
        profile="security",
        remove_metadata=True,
        remove_gps=True,
        remove_author=True,
        remove_timestamps=True,
        remove_comments=True,
        remove_embedded_files=True,
        remove_macros=True,
        remove_javascript=True,
        remove_external_links=True,
        remove_hyperlinks=True,
        reencode_image=True,
        flatten_image=False,
        flatten_document=True,
        rasterize_pages=False,
        strip_active_content=True,
        strip_external_resources=True
    ),
    "maximum": SanitizationOptions(
        profile="maximum",
        remove_metadata=True,
        remove_gps=True,
        remove_author=True,
        remove_timestamps=True,
        remove_comments=True,
        remove_embedded_files=True,
        remove_macros=True,
        remove_javascript=True,
        remove_external_links=True,
        remove_hyperlinks=True,
        reencode_image=True,
        flatten_image=True,
        flatten_document=True,
        rasterize_pages=True,
        strip_active_content=True,
        strip_external_resources=True
    )
}

def get_profile_options(profile_name: str) -> SanitizationOptions:
    """Return default options for named profile, falling back to privacy."""
    return PROFILES.get(profile_name.lower(), PROFILES["privacy"]).copy(deep=True)
