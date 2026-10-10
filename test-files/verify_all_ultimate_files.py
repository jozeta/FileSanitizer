#!/usr/bin/env python3
import os, sys, time, json, urllib.request, urllib.error
from pathlib import Path

BASE_URL = "http://localhost:8000"
FILES_DIR = Path(__file__).resolve().parent

test_files = sorted(list(FILES_DIR.glob("ultimate_detectio.*")))
print(f"[*] Found {len(test_files)} test files to verify:")
for f in test_files:
    print(f"  - {f.name}")

results = {}

def upload_file(fpath):
    fname = fpath.name
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    data = bytearray()
    data.extend(f"--{boundary}\r\n".encode("utf-8"))
    data.extend(f'Content-Disposition: form-data; name="files"; filename="{fname}"\r\n'.encode("utf-8"))
    data.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    data.extend(fpath.read_bytes())
    data.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    
    req = urllib.request.Request(
        f"{BASE_URL}/api/files",
        data=bytes(data),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

for fpath in test_files:
    fname = fpath.name
    print(f"\n==================================================")
    print(f"[*] Uploading and Analyzing: {fname}")
    try:
        upload_data = upload_file(fpath)
    except Exception as e:
        print(f"[-] Upload failed: {e}")
        results[fname] = {"success": False, "error": f"Upload failed: {e}"}
        continue
        
    job_id = upload_data["jobs"][0]["job_id"]
    print(f"[+] Queued Job ID: {job_id}")
    
    # Poll for completion
    for _ in range(40):
        time.sleep(1)
        try:
            st = get_json(f"{BASE_URL}/api/jobs/{job_id}")
            if st.get("state") in ["ANALYZED", "COMPLETED", "FAILED"]:
                break
        except Exception:
            pass
                
    # Get analysis
    try:
        data = get_json(f"{BASE_URL}/api/jobs/{job_id}/analysis")
    except Exception as e:
        print(f"[-] Analysis fetch failed: {e}")
        results[fname] = {"success": False, "error": f"Analysis fetch failed: {e}"}
        continue
        
    cat = data.get("category")
    risk = data.get("risk", {}).get("level") if data.get("risk") else "UNKNOWN"
    findings = [f.get("title") for f in data.get("findings", [])]
    mitre_list = data.get("mitre_attack") or []
    mitre = [m.get("technique_id", "") + " - " + m.get("technique_name", "") for m in mitre_list]
    
    print(f"[+] Category: {cat} | Risk: {risk}")
    print(f"[+] Findings ({len(findings)}):")
    for f in findings[:5]:
        print(f"    * {f}")
    if len(findings) > 5:
        print(f"    * ... and {len(findings)-5} more")
    print(f"[+] MITRE ATT&CK Mapped: {len(mitre)} techniques ({mitre[:3]})")
    
    # Format-specific validations
    details = {}
    if cat == "script":
        st = data.get("script_triage") or {}
        details["script_type"] = st.get("script_type")
        details["risk_score"] = st.get("risk_score")
        details["patterns"] = len(st.get("detected_patterns") or [])
        print(f"    [Script] Type: {details['script_type']} | Score: {details['risk_score']} | Patterns: {details['patterns']}")
    elif cat in ["binary", "executable"]:
        bi = data.get("binary_info") or {}
        details["imphash"] = bi.get("imphash")
        details["disasm_findings"] = len(bi.get("disassembly_findings") or [])
        details["anti_analysis"] = len(bi.get("anti_analysis") or [])
        details["authenticode"] = bi.get("authenticode", {}).get("has_signature")
        details["elf"] = bool(bi.get("elf_mitigations"))
        print(f"    [Binary] Imphash: {details['imphash']} | Disasm findings: {details['disasm_findings']} | Anti-analysis: {details['anti_analysis']} | Auth: {details['authenticode']} | ELF: {details['elf']}")
    elif cat == "email":
        ei = data.get("email_info") or {}
        details["vip"] = ei.get("is_vip_impersonation")
        details["homoglyphs"] = ei.get("has_homoglyphs")
        details["thread_hijack"] = ei.get("thread_hijacking", {}).get("is_hijacked")
        details["html_smuggling"] = ei.get("html_smuggling", {}).get("detected")
        print(f"    [Email] VIP: {details['vip']} | Homoglyphs: {details['homoglyphs']} | Thread hijack: {details['thread_hijack']} | HTML smuggle: {details['html_smuggling']}")
    elif cat == "image":
        im = data.get("image", {})
        details["has_gps"] = im.get("has_gps")
        details["has_exif"] = im.get("has_exif")
        details["has_overlay"] = im.get("overlay", {}).get("has_overlay")
        details["has_stego"] = im.get("steganography", {}).get("stego_detected")
        print(f"    [Image] GPS: {details['has_gps']} | EXIF: {details['has_exif']} | Overlay: {details['has_overlay']} | Stego: {details['has_stego']}")
    elif cat == "office":
        off = data.get("office", {})
        details["macros"] = off.get("has_macros")
        details["template_inj"] = off.get("remote_template_injection")
        details["stomping"] = off.get("vba_stomping")
        print(f"    [Office] Macros: {details['macros']} | Template: {details['template_inj']} | Stomping: {details['stomping']}")
    
    results[fname] = {
        "success": True,
        "category": cat,
        "risk": risk,
        "findings_count": len(findings),
        "mitre_count": len(mitre),
        "details": details
    }

print("\n\n==================================================")
print("[*] SUMMARY OF ALL 21 TEST FILES:")
all_passed = True
for fname, res in results.items():
    if res.get("success"):
        print(f"  [PASS] {fname:25} | Cat: {res['category']:10} | Risk: {res['risk']:11} | Findings: {res['findings_count']:2} | MITRE: {res['mitre_count']:2}")
    else:
        all_passed = False
        print(f"  [FAIL] {fname:25} | Error: {res.get('error')}")

print(f"\nAll files successfully verified: {all_passed}")
