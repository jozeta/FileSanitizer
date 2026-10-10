#!/usr/bin/env python3
"""
Generate a comprehensive suite of .eml and .msg test files:
1. clean_welcome_notification.eml & .msg
2. phishing_credential_alert.eml & .msg (tracking pixel, suspicious link, spoofed sender)
3. invoice_with_macro_attachment.eml & .msg (dangerous attachment)
4. spoofed_authentication_failure.eml (SPF/DKIM fail headers)
"""

import os
import struct
from pathlib import Path
import email.message
from email import policy
import olefile


OUT_DIR = Path(__file__).resolve().parent

def build_ole_msg(out_path: Path, subject: str, from_addr: str, body_text: str, body_html: str, attachments=None, reply_to: str = ""):
    """
    Construct a valid Microsoft Outlook Compound File (.msg) using olefile structure.
    Streams:
    - __substg1.0_0037001F (Subject)
    - __substg1.0_0C1A001F (From Name / Address)
    - __substg1.0_1000001F (Body text)
    - __substg1.0_10130102 (HTML body)
    - __substg1.0_007D001F (Transport headers)
    - __substg1.0_0050001F (Reply-To)
    """
    import tempfile
    import struct

    # Transport headers string
    extra_headers = f"Reply-To: {reply_to}\r\n" if reply_to else ""
    transport_headers = (
        f"From: {from_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"{extra_headers}"
        f"Date: Fri, 26 Sep 2026 09:30:00 +0000\r\n"
        f"Message-ID: <msg-{os.urandom(8).hex()}@filesanitizer.test>\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
    )

    try:
        _write_compound_msg(out_path, subject, from_addr, body_text, body_html, transport_headers, attachments, reply_to)
    except Exception as e:
        print(f"Error writing OLE .msg {out_path.name}: {e}")

def _write_compound_msg(out_path: Path, subject: str, from_addr: str, body_text: str, body_html: str, transport_headers: str, attachments=None, reply_to: str = ""):
    """
    Writes a valid OLE Compound Binary File with Outlook streams:
    - Directory entries for Root, Subject, Sender, Body, HTML Body, Transport Headers, and Attachments.
    """
    sector_size = 512
    # Prepare streams (name, data_bytes)
    streams = [
        ("__substg1.0_0037001F", subject.encode('utf-16le')),
        ("__substg1.0_0C1A001F", from_addr.encode('utf-16le')),
        ("__substg1.0_1000001F", body_text.encode('utf-16le')),
        ("__substg1.0_10130102", body_html.encode('utf-8')),
        ("__substg1.0_007D001F", transport_headers.encode('utf-16le')),
    ]
    if reply_to:
        streams.append(("__substg1.0_0050001F", reply_to.encode('utf-16le')))

    if attachments:
        for idx, (att_name, att_bytes) in enumerate(attachments, start=1):
            storage_pfx = f"__attach_version1.0_#{idx:08d}/"
            streams.append((f"{storage_pfx}__substg1.0_3707001F", att_name.encode('utf-16le')))
            streams.append((f"{storage_pfx}__substg1.0_37010102", att_bytes))

    # Construct OLE file structure
    # Header (sector 0):
    # Offset 0: Header Signature (8 bytes) D0 CF 11 E0 A1 B1 1A E1
    # Offset 28: Byte order FE FF (little endian)
    # Offset 30: Sector size shift: 9 (2^9 = 512)
    # Offset 32: Mini sector shift: 6 (2^6 = 64)
    # Offset 44: Number of FAT sectors
    # Offset 48: First Directory sector
    # Offset 76: First 109 FAT sector locations
    raw = bytearray()
    hdr = bytearray(512)
    hdr[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    hdr[28:30] = struct.pack("<H", 0xFFFE)
    hdr[30:32] = struct.pack("<H", 9)  # 512 bytes
    hdr[32:34] = struct.pack("<H", 6)  # 64 bytes
    hdr[44:48] = struct.pack("<I", 1)  # 1 FAT sector
    hdr[48:52] = struct.pack("<I", 1)  # Directory sector at sector 1
    hdr[56:60] = struct.pack("<I", 4096)  # Min stream cutoff
    hdr[60:64] = struct.pack("<I", 0xFFFFFFFE)  # Mini FAT chain end
    hdr[64:68] = struct.pack("<I", 0)  # Mini FAT sectors
    hdr[68:72] = struct.pack("<I", 0xFFFFFFFE)  # DIFAT chain end
    hdr[76:80] = struct.pack("<I", 0)  # FAT sector 0 is at sector 0 of payload (file offset 512)
    for i in range(1, 109):
        hdr[76 + i*4 : 80 + i*4] = struct.pack("<I", 0xFFFFFFFF)

    # Directory entries count
    dir_entries_count = 1 + len(streams)
    num_dir_sectors = (dir_entries_count * 128 + 511) // 512

    # Sector 0: FAT
    # Sector 1 to num_dir_sectors: Directory
    # Following sectors: data
    data_sec_start = 1 + num_dir_sectors
    current_sec = data_sec_start

    stream_info = []
    data_sectors_bytes = bytearray()
    for s_name, s_bytes in streams:
        num_sec = max(8, (len(s_bytes) + 511) // 512)
        s_len = max(4096, len(s_bytes))
        start_sec = current_sec
        stream_info.append((s_name, s_len, start_sec, num_sec))
        padded = s_bytes.ljust(num_sec * 512, b"\x00")
        data_sectors_bytes.extend(padded)
        current_sec += num_sec


    # Build FAT
    fat = bytearray(512)
    # Initialize all entries to FREE (0xFFFFFFFF)
    for i in range(128):
        fat[i*4 : (i+1)*4] = struct.pack("<I", 0xFFFFFFFF)

    # Sector 0 is FAT end
    fat[0:4] = struct.pack("<I", 0xFFFFFFFD)  # FAT sector itself

    # Dir sectors chain
    for ds in range(1, num_dir_sectors):
        fat[ds*4 : (ds+1)*4] = struct.pack("<I", ds + 1)
    fat[num_dir_sectors*4 : (num_dir_sectors+1)*4] = struct.pack("<I", 0xFFFFFFFE)  # Dir end

    # Data sectors chain
    for s_name, s_len, start_sec, num_sec in stream_info:
        for s in range(num_sec):
            sec_idx = start_sec + s
            next_val = sec_idx + 1 if s < num_sec - 1 else 0xFFFFFFFE
            if sec_idx < 128:
                fat[sec_idx*4 : (sec_idx+1)*4] = struct.pack("<I", next_val)

    # Build Directory Entries (128 bytes each)
    dir_bytes = bytearray(num_dir_sectors * 512)

    # Entry 0: Root Entry
    root_entry = bytearray(128)
    root_name = "Root Entry\x00".encode('utf-16le')
    root_entry[0:len(root_name)] = root_name
    root_entry[64:66] = struct.pack("<H", len(root_name))
    root_entry[66] = 5  # StgType: Root Storage
    root_entry[67] = 1  # Black
    root_entry[68:72] = struct.pack("<I", 0xFFFFFFFF)  # Left
    root_entry[72:76] = struct.pack("<I", 0xFFFFFFFF)  # Right
    root_entry[76:80] = struct.pack("<I", 1 if len(streams) > 0 else 0xFFFFFFFF)  # Child
    root_entry[116:120] = struct.pack("<I", 0xFFFFFFFE)  # Start of Mini-stream
    root_entry[120:124] = struct.pack("<I", 0)  # Mini-stream size
    dir_bytes[0:128] = root_entry

    # Add stream entries
    for idx, (s_name, s_len, start_sec, num_sec) in enumerate(stream_info, start=1):
        s_entry = bytearray(128)
        # Only take base stream name (up to 31 chars)
        disp_name = s_name.split("/")[-1][:31] + "\x00"
        name_utf16 = disp_name.encode('utf-16le')
        s_entry[0:len(name_utf16)] = name_utf16
        s_entry[64:66] = struct.pack("<H", len(name_utf16))
        s_entry[66] = 2  # StgType: Stream
        s_entry[67] = 1  # Color: Black
        s_entry[68:72] = struct.pack("<I", 0xFFFFFFFF)  # Left
        # Link right sibling if exists
        right_sibling = (idx + 1) if idx < len(stream_info) else 0xFFFFFFFF
        s_entry[72:76] = struct.pack("<I", right_sibling)  # Right
        s_entry[76:80] = struct.pack("<I", 0xFFFFFFFF)  # Child
        s_entry[116:120] = struct.pack("<I", start_sec)
        s_entry[120:124] = struct.pack("<I", s_len)
        dir_bytes[idx*128 : (idx+1)*128] = s_entry

    # Combine into file
    with open(out_path, "wb") as f:
        f.write(hdr)
        f.write(fat)
        f.write(dir_bytes)
        f.write(data_sectors_bytes)

def generate_clean_email():
    """1. Clean Email (.eml and .msg)"""
    eml_path = OUT_DIR / "clean_welcome_newsletter.eml"
    msg_path = OUT_DIR / "clean_welcome_newsletter.msg"

    msg = email.message.EmailMessage()
    msg['From'] = "Support Team <support@company.com>"
    msg['To'] = "analyst@enterprise.org"
    msg['Subject'] = "Welcome to the New Security Portal"
    msg['Date'] = "Fri, 26 Sep 2026 08:00:00 +0000"
    msg['Message-ID'] = "<welcome-20260926@company.com>"
    msg['Received-SPF'] = "pass (domain of company.com designates 192.0.2.1 as permitted sender)"
    msg['Authentication-Results'] = "spf=pass dkim=pass (signature verified) header.i=@company.com"

    text_body = "Hello Analyst,\n\nWelcome to your new enterprise security portal. Access your dashboard at https://example.com/dashboard.\n\nBest regards,\nSecurity Team"
    html_body = "<html><body><h3>Welcome to FileSanitizer Portal</h3><p>Access your dashboard at <a href='https://example.com/dashboard'>example.com/dashboard</a>.</p></body></html>"

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    with open(eml_path, "wb") as f:
        f.write(msg.as_bytes())

    build_ole_msg(msg_path, "Welcome to the New Security Portal", "support@company.com", text_body, html_body)
    print(f"Generated clean email: {eml_path.name} & {msg_path.name}")

def generate_phishing_email():
    """2. Phishing Email (.eml and .msg) with tracking pixel and credential harvest link"""
    eml_path = OUT_DIR / "phishing_credential_alert.eml"
    msg_path = OUT_DIR / "phishing_credential_alert.msg"

    msg = email.message.EmailMessage()
    # Display name spoofing
    msg['From'] = "IT Helpdesk <admin@microsoft-security-portal.xyz>"
    msg['To'] = "victim@target-corp.com"
    msg['Subject'] = "URGENT: Password Expiry Notification - Verification Required"
    msg['Date'] = "Fri, 26 Sep 2026 08:15:00 +0000"
    msg['Message-ID'] = "<urgent-auth-action@phish-domain.xyz>"
    msg['Reply-To'] = "attacker-collector@mail-harvest.xyz"

    text_body = "Your corporate password expires today. Please verify your identity immediately at http://login-security-update.xyz/verify to prevent account lock."
    html_body = (
        "<html><body>"
        "<h2 style='color:red;'>Action Required: Immediate Account Verification</h2>"
        "<p>Your session will be terminated in 24 hours unless you confirm your password.</p>"
        "<p><a href='http://login-security-update.xyz/verify' style='font-size:16px;font-weight:bold;'>Click Here to Verify Password</a></p>"
        "<!-- Hidden tracking beacon -->"
        "<img src='http://tracking.analytics-pixel.top/pixel.gif' width='1' height='1' style='display:none;' alt='tracker'>"
        "</body></html>"
    )

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    with open(eml_path, "wb") as f:
        f.write(msg.as_bytes())

    build_ole_msg(
        msg_path,
        "URGENT: Password Expiry Notification - Verification Required",
        "admin@microsoft-security-portal.xyz",
        text_body,
        html_body,
        reply_to="attacker-collector@mail-harvest.xyz"
    )
    print(f"Generated phishing email: {eml_path.name} & {msg_path.name}")

def generate_macro_attachment_email():
    """3. Email with Dangerous Macro Attachment (.eml and .msg)"""
    eml_path = OUT_DIR / "invoice_with_macro_attachment.eml"
    msg_path = OUT_DIR / "invoice_with_macro_attachment.msg"

    msg = email.message.EmailMessage()
    msg['From'] = "Accounts Payable <billing@invoicing-services.net>"
    msg['To'] = "finance@target-corp.com"
    msg['Subject'] = "Overdue Invoice #INV-2026-994 (Final Notice)"
    msg['Date'] = "Fri, 26 Sep 2026 08:30:00 +0000"
    msg['Message-ID'] = "<invoice-overdue-994@invoicing-services.net>"

    text_body = "Please find attached your overdue invoice. Open the attached document and enable content to review payment terms."
    html_body = "<html><body><p>Please review the attached invoice. Note: You must <b>Enable Content / Enable Macros</b> to view invoice line items.</p></body></html>"

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    # Dummy macro document attachment payload
    vba_docm_payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00word/vbaProject.bin" + (b"\x90" * 256) + b"Sub AutoOpen()\nShell('calc.exe')\nEnd Sub"
    msg.add_attachment(vba_docm_payload, maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename="Invoice_Sep2026.docm")

    with open(eml_path, "wb") as f:
        f.write(msg.as_bytes())

    build_ole_msg(
        msg_path,
        "Overdue Invoice #INV-2026-994 (Final Notice)",
        "billing@invoicing-services.net",
        text_body,
        html_body,
        attachments=[("Invoice_Sep2026.docm", vba_docm_payload)]
    )
    print(f"Generated macro attachment email: {eml_path.name} & {msg_path.name}")

def generate_spoofed_auth_fail_email():
    """4. Email with SPF/DKIM Authentication Failure (.eml)"""
    eml_path = OUT_DIR / "spoofed_dkim_spf_failure.eml"

    msg = email.message.EmailMessage()
    msg['From'] = "CEO Office <executive@trusted-bank.com>"
    msg['To'] = "treasury@target-corp.com"
    msg['Subject'] = "Confidential Wire Transfer Authorization"
    msg['Date'] = "Fri, 26 Sep 2026 08:45:00 +0000"
    msg['Message-ID'] = "<wire-transfer-confidential@spoofed-host.net>"
    # Failed authentication markers
    msg['Received-SPF'] = "fail (domain of trusted-bank.com does not designate 198.51.100.22 as permitted sender)"
    msg['Authentication-Results'] = "mx.google.com; spf=fail (google.com: domain of executive@trusted-bank.com does not designate 198.51.100.22 as permitted sender) smtp.mailfrom=executive@trusted-bank.com; dkim=fail header.i=@trusted-bank.com"
    msg['Received'] = "from mail.spoofed-c2-network.net ([198.51.100.22]) by mx.target-corp.com"

    text_body = "Please execute urgent wire transfer to the account specified in our previous discussion.\n\nAccount: SE4550000000058398257466\nAmount: $250,000"
    msg.set_content(text_body)

    with open(eml_path, "wb") as f:
        f.write(msg.as_bytes())

    print(f"Generated spoofed authentication email: {eml_path.name}")

if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    generate_clean_email()
    generate_phishing_email()
    generate_macro_attachment_email()
    generate_spoofed_auth_fail_email()
    print("All .eml and .msg test files successfully created in test-files/")
