# FileSanitizer Test Files Suite

This directory contains test files specifically crafted to exercise FileSanitizer's security analyzers, Content Disarm & Reconstruction (CDR) engines, metadata extractors, and antivirus scanners.

| File Name | Intended Security Triggers | Expected App Reaction |
| :--- | :--- | :--- |
| `image_gps_exif_metadata.jpg` | Embedded GPS coordinates (Stockholm: 59°19'45" N, 18°04'07" E), Camera Hardware (Sony Alpha 7 IV), Author (Jane Doe), Software. | Detected in **Location** & **Camera** metadata tabs. Flagged as **SENSITIVE**. Sanitization strips EXIF/GPS and re-encodes. |
| `clean_image.png` | Standard clean PNG with zero metadata or scripts. | Evaluated as **CLEAN**. |
| `suspicious_javascript_actions.pdf` | Embedded JavaScript (`app.alert`), `/Launch` command, OpenAction trigger, external URL, and embedded CSV attachment. | Classified as **HIGH RISK**. Flags JS alert, Launch action, and attachments. "Maximum Sanitization" rasterizes pages to pure pixel images. |
| `clean_document.pdf` | Benign clean PDF document with plain text. | Evaluated as **CLEAN**. |
| `office_vba_macro_template_injection.docm` | Embedded VBA macro binary stream (`vbaProject.bin`), external template injection relationship (`attachedTemplate`), Author metadata. | Triggers prominent **MACROS DETECTED** banner. Classified as **HIGH RISK**. Sanitizer purges macro streams and neutralizes external rels. |
| `clean_office_document.docx` | Standard OpenXML document without macros or external targets. | Evaluated as **CLEAN**. |
| `active_content_xss.svg` | Embedded `<script>` block, inline `onload` DOM event handler, `javascript:` URI, and external tracker beacon image. | Flagged as active content risk. Sanitizer strips scripts or rasterizes to PNG. |
| `phishing_login_with_iframes.html` | Embedded `<iframe>`, credential `<form>`, inline scripts, and `<meta http-equiv="refresh">` redirect. | Flagged as interactive form & script risk. Sanitizer decomposes iframes, neutralizes forms, and strips scripts. |
| `dangerous_archive_with_traversal.zip` | Directory traversal entry (`../../etc/passwd`), executable batch script (`.bat`), and PowerShell payload (`.ps1`). | Flagged with **Critical Path Traversal** and **Executable Payload** findings. Sanitizer excludes dangerous members. |
| `eicar_standard_av_test.txt` | Standard, inert 68-character EICAR antivirus test signature. | ClamAV detects **`Eicar-Test-Signature`** with status **MALICIOUS**. Original download and standard sanitization are blocked. |
| `spreadsheet_formula_injection.csv` | CSV cells starting with formula execution prefixes (`=cmd\|...`, `+powershell...`, `@SUM...`). | Flagged as **Spreadsheet Formula Injection Detected**. Sanitizer escapes formula prefixes with leading quotes (`'`). |
