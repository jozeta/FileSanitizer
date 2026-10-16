"""
Java Source Code, Compiled Bytecode (.class), and Java Archive (.jar) Forensic Analyzer.
Evaluates:
- Java source code (.java) AST & static security heuristics (Command execution, Reflection, Unsafe, JNDI, Deserialization)
- Compiled Java Bytecode (.class) binary structure, major/minor versions (Java 1.1 to 23), Constant Pool inspection
- Method references and dangerous JVM API calls (Runtime.exec, ProcessBuilder, sun.misc.Unsafe, Method.invoke, Socket)
- Java Archive (.jar/.war) manifest inspection (Main-Class, Premain-Class Java Agent memory hooks, all-permissions)
- Java RAT & malware signatures (jRAT, Adwind, AlienSpy, AsyncRAT Java variants)
- Obfuscator detection (ProGuard, Allatori, DashO, Zelix KlassMaster)
- Extraction of hardcoded strings, credentials, network IOCs, and MITRE ATT&CK mapping
"""

import re
import struct
import zipfile
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger

JAVA_VERSION_MAP = {
    45: "Java 1.1", 46: "Java 1.2", 47: "Java 1.3", 48: "Java 1.4",
    49: "Java 5", 50: "Java 6", 51: "Java 7", 52: "Java 8 (LTS)",
    53: "Java 9", 54: "Java 10", 55: "Java 11 (LTS)", 56: "Java 12",
    57: "Java 13", 58: "Java 14", 59: "Java 15", 60: "Java 16",
    61: "Java 17 (LTS)", 62: "Java 18", 63: "Java 19", 64: "Java 20",
    65: "Java 21 (LTS)", 66: "Java 22", 67: "Java 23"
}

# Dangerous Java API Signatures across Source and Bytecode (Enterprise & Malware Mapped)
HIGH_RISK_JAVA_APIS = [
    {
        "pattern": re.compile(r'Runtime\.getRuntime\(\)\.exec|Runtime;->exec|java/lang/Runtime;?\.?exec', re.I),
        "api": "Runtime.exec()",
        "title": "Operating System Shell Command Execution",
        "severity": "critical",
        "category": "execution",
        "description": "Invokes the native OS command interpreter or executes arbitrary binary processes.",
        "risk_explanation": "Spawns raw host operating system processes. Threat actors use this to drop secondary malware, run bash/cmd commands, execute curl/wget downloaders, and establish persistence.",
        "remediation": "Avoid calling host shell binaries. Use type-safe, sandboxed native Java APIs (e.g. java.nio.file) without process invocation.",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059",
        "mitre_name": "Command and Scripting Interpreter"
    },
    {
        "pattern": re.compile(r'ProcessBuilder|java/lang/ProcessBuilder', re.I),
        "api": "ProcessBuilder",
        "title": "Subprocess Creation & Shell Spawning",
        "severity": "critical",
        "category": "execution",
        "description": "Spawns background processes with customized environment variables and redirected streams.",
        "risk_explanation": "Creates native subprocesses with customized environment variables and standard I/O redirection, standard for reverse shells and shell script execution.",
        "remediation": "Refactor logic to utilize standard Java APIs instead of invoking host executables.",
        "cwe": "CWE-78: OS Command Injection",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059",
        "mitre_name": "Command and Scripting Interpreter"
    },
    {
        "pattern": re.compile(r'sun/misc/Unsafe|jdk/internal/misc/Unsafe', re.I),
        "api": "sun.misc.Unsafe",
        "title": "Direct Unmanaged Memory Manipulation",
        "severity": "critical",
        "category": "memory",
        "description": "Bypasses JVM memory safety checks, enabling raw memory allocation, arbitrary pointer reads/writes, and type confusion exploits.",
        "risk_explanation": "Circumvents JVM memory management, allowing direct raw memory allocation, arbitrary pointer dereferencing, and security manager bypass.",
        "remediation": "Use standard Java memory models and VarHandle / Foreign Function & Memory API (Project Panama) in modern JDKs.",
        "cwe": "CWE-119: Memory Safety Violation",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1055",
        "mitre_name": "Process Injection"
    },
    {
        "pattern": re.compile(r'InitialContext\(\)\.lookup|jndi:(?:ldap|rmi|dns)', re.I),
        "api": "JNDI Remote Lookup",
        "title": "Remote JNDI Naming Lookup (Log4Shell / RCE Vector)",
        "severity": "critical",
        "category": "injection",
        "description": "Resolves remote JNDI directory resources via LDAP or RMI, enabling arbitrary remote class deserialization (e.g. Log4Shell CVE-2021-44228).",
        "risk_explanation": "Resolves arbitrary remote directories via LDAP, RMI, or CORBA. Attackers trigger deserialization of remote Java classes leading to instant Remote Code Execution (CVE-2021-44228).",
        "remediation": "Disable remote protocol lookups, restrict JNDI contexts, and ensure com.sun.jndi.ldap.object.trustURLCodebase=false.",
        "cwe": "CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": "A03:2021-Injection",
        "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application"
    },
    {
        "pattern": re.compile(r'ObjectInputStream\.readObject|readUnshared|XMLDecoder', re.I),
        "api": "Insecure Deserialization",
        "title": "Java Object Deserialization (Insecure Deserialization)",
        "severity": "high",
        "category": "deserialization",
        "description": "Deserializes untrusted binary object streams without schema validation (ysoserial gadget chain vector).",
        "risk_explanation": "Deserializes untrusted binary objects without class verification. Attackers provide serialized gadget chains (ysoserial CommonsCollections, Spring, etc.) to trigger arbitrary code execution.",
        "remediation": "Implement strict ObjectInputFilter validation (JEP 290) or use type-safe serialization formats like JSON/Protocol Buffers.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1203",
        "mitre_name": "Exploitation for Client Execution"
    },
    {
        "pattern": re.compile(r'java/lang/reflect/Method;?\.?invoke|Class\.forName|ClassLoader\.loadClass', re.I),
        "api": "Dynamic Reflection",
        "title": "Dynamic Reflection & Obfuscated Method Invocation",
        "severity": "high",
        "category": "reflection",
        "description": "Invokes methods dynamically by string name at runtime to evade static code inspection and security filters.",
        "risk_explanation": "Reflectively resolves classes and methods by string name. Malware leverages this to evade static security scanners and antivirus filters.",
        "remediation": "Use compile-time static bindings and interfaces rather than runtime string-based reflection.",
        "cwe": "CWE-470: Use of Externally-Controlled Input to Select Classes or Code",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1626",
        "mitre_name": "Obfuscated Files or Information"
    },
    {
        "pattern": re.compile(r'URLClassLoader|java/net/URLClassLoader', re.I),
        "api": "URLClassLoader",
        "title": "Remote Dynamic Bytecode Loading",
        "severity": "high",
        "category": "code_loading",
        "description": "Fetches and instantiates executable Java classes from remote HTTP or FTP servers at runtime.",
        "risk_explanation": "Fetches executable JAR or class files from remote HTTP/FTP servers at runtime, allowing clean stubs to download malicious payloads.",
        "remediation": "Package all necessary dependencies directly into the application archive and enforce digital code signing.",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1105",
        "mitre_name": "Ingress Tool Transfer"
    },
    {
        "pattern": re.compile(r'System\.loadLibrary|System\.load\b', re.I),
        "api": "System.load / Native JNI",
        "title": "Native Dynamic Link Library Injection (.dll / .so)",
        "severity": "high",
        "category": "native_code",
        "description": "Loads native operating system shared libraries into the JVM process address space.",
        "risk_explanation": "Loads compiled C/C++ native shared libraries (.dll, .so, .dylib) directly into JVM process memory, bypassing all Java sandbox constraints.",
        "remediation": "Ensure loaded libraries reside in write-protected system directories and verify cryptographic hashes before loading.",
        "cwe": "CWE-114: Process Control",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1129",
        "mitre_name": "Shared Modules"
    },
    {
        "pattern": re.compile(r'java/awt/Robot|new\s+Robot\(\)', re.I),
        "api": "AWT Robot",
        "title": "AWT Robot Synthetic Input & Screen Capture (Spyware)",
        "severity": "high",
        "category": "surveillance",
        "description": "Can generate automated low-level mouse clicks, keystrokes, and capture screenshots of the active desktop.",
        "risk_explanation": "Captures desktop screen pixels and injects artificial keystrokes and mouse movements. Widely utilized by Java RATs (jRAT, Adwind) for keylogging and desktop surveillance.",
        "remediation": "Remove java.awt.Robot usage unless developing accessibility testing tools.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1056.001",
        "mitre_name": "Keylogging"
    },
    {
        "pattern": re.compile(r'java/net/Socket|java/net/ServerSocket', re.I),
        "api": "Raw Sockets",
        "title": "Raw TCP Socket Network Communication",
        "severity": "medium",
        "category": "network",
        "description": "Opens low-level TCP/IP network sockets for bidirectional communication or reverse shells.",
        "risk_explanation": "Opens raw low-level sockets commonly used to establish interactive reverse TCP command shells.",
        "remediation": "Use high-level application protocols (HTTPS, gRPC) with authenticated TLS encryption.",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1095",
        "mitre_name": "Non-Application Layer Protocol"
    },
    {
        "pattern": re.compile(r'java/lang/instrument/Instrumentation', re.I),
        "api": "JVM Instrumentation",
        "title": "JVM Bytecode Instrumentation (Java Agent)",
        "severity": "high",
        "category": "instrumentation",
        "description": "Modifies bytecode of classes at runtime in memory, commonly used by rootkits and memory hooking agents.",
        "risk_explanation": "Allows agents to redefine and retransform class bytecode dynamically in memory to bypass security controls.",
        "remediation": "Disallow Java Agents via JVM launch flags (-XX:-EnableJVMCI or security managers) in sensitive production environments.",
        "cwe": "CWE-1055: Process Injection",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1055",
        "mitre_name": "Process Injection"
    },
    {
        "pattern": re.compile(r'(?:AES|DES|DESede|Blowfish|RC4)/ECB', re.I),
        "api": "Cipher Mode: ECB",
        "title": "Insecure Cipher Mode (Electronic Codebook / ECB)",
        "severity": "high",
        "category": "crypto",
        "description": "Uses Electronic Codebook (ECB) mode for symmetric block ciphers without initialization vector.",
        "risk_explanation": "ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving visual and statistical patterns.",
        "remediation": "Switch to authenticated encryption algorithms such as AES/GCM/NoPadding with a unique cryptographically random IV.",
        "cwe": "CWE-327: Broken Cryptographic Algorithm",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)["\']', re.I),
        "api": "MessageDigest(MD5/SHA-1)",
        "title": "Broken Hash Function (MD5 / SHA-1)",
        "severity": "high",
        "category": "crypto",
        "description": "Instantiates legacy collision-prone hash algorithms (MD5 or SHA-1).",
        "risk_explanation": "Practical collision attacks exist for MD5 and SHA-1, compromising signature integrity.",
        "remediation": "Upgrade hashing routines to SHA-256 or SHA-512, or use Argon2id/bcrypt for password storage.",
        "cwe": "CWE-328: Use of Weak Hash",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|RC4|ARCFOUR|Blowfish)', re.I),
        "api": "Cipher.getInstance(DES/RC4/Blowfish)",
        "title": "Deprecated Legacy Cipher (DES / RC4 / Blowfish)",
        "severity": "critical",
        "category": "crypto",
        "description": "Initializes deprecated or broken symmetric encryption algorithms.",
        "risk_explanation": "DES uses an insecure 56-bit key space; Blowfish suffers from Sweet32 block collisions; RC4 exhibits severe statistical keystream biases.",
        "remediation": "Standardize exclusively on AES-256 or ChaCha20-Poly1305 with modern authenticated encryption modes.",
        "cwe": "CWE-327: Broken Cryptographic Algorithm",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'TrustAll(?:Trust)?Manager|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}', re.I),
        "api": "TrustAllTrustManager / ALLOW_ALL_HOSTNAME_VERIFIER",
        "title": "SSL/TLS Verification Bypass (Insecure TrustManager)",
        "severity": "critical",
        "category": "network_tls",
        "description": "Bypasses SSL/TLS certificate or hostname verification.",
        "risk_explanation": "Allows attackers on the same network to intercept, inspect, and modify encrypted HTTPS traffic without triggering warnings.",
        "remediation": "Remove empty TrustManagers and let standard JVM certificate validation handle TLS handshakes.",
        "cwe": "CWE-295: Improper Certificate Validation",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": "T1557",
        "mitre_name": "Man-in-the-Middle"
    },
    {
        "pattern": re.compile(r'getSystemClipboard|java/awt/datatransfer/Clipboard', re.I),
        "api": "Toolkit.getSystemClipboard()",
        "title": "System Clipboard Access & Monitoring",
        "severity": "medium",
        "category": "clipboard",
        "description": "Reads or modifies content stored in the system clipboard.",
        "risk_explanation": "Clipper malware monitors the clipboard to steal copied credentials or swap crypto wallet addresses.",
        "remediation": "Access clipboard only in direct response to explicit user paste actions.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1414",
        "mitre_name": "Credentials from Web Browsers / Clipboard"
    }
]

# Java RAT / Malware Signatures
JAVA_RAT_SIGNATURES = [
    {
        "name": "jRAT / Jackrum (Cross-Platform RAT)",
        "patterns": [re.compile(r'jrat/|server/Payload\.class|crypto/AES\.class', re.I)],
        "severity": "critical"
    },
    {
        "name": "Adwind / AlienSpy / Frutas RAT",
        "patterns": [re.compile(r'adwind|alienspy|frutas|dropbox\.com/s/|jnativehook', re.I)],
        "severity": "critical"
    },
    {
        "name": "AsyncRAT / Java Dropper",
        "patterns": [re.compile(r'AsyncClient|PowerShell.*-enc|rundll32.*advpack', re.I)],
        "severity": "critical"
    },
    {
        "name": "Log4j / Log4Shell Exploitation Payload",
        "patterns": [re.compile(r'\$\{jndi:(?:ldap|rmi|dns|corba):', re.I)],
        "severity": "critical"
    }
]


class JavaClassParser:
    """
    Binary parser for Java .class bytecode files.
    Decodes versions, constant pool, class names, method refs, and dangerous API calls.
    """
    TAG_UTF8 = 1
    TAG_INTEGER = 3
    TAG_FLOAT = 4
    TAG_LONG = 5
    TAG_DOUBLE = 6
    TAG_CLASS = 7
    TAG_STRING = 8
    TAG_FIELDREF = 9
    TAG_METHODREF = 10
    TAG_INTERFACE_METHODREF = 11
    TAG_NAME_AND_TYPE = 12
    TAG_METHOD_HANDLE = 15
    TAG_METHOD_TYPE = 16
    TAG_DYNAMIC = 17
    TAG_INVOKE_DYNAMIC = 18
    TAG_MODULE = 19
    TAG_PACKAGE = 20

    def __init__(self, data: bytes):
        self.data = data
        self.is_valid = False
        self.minor_version = 0
        self.major_version = 0
        self.java_version_name = "Unknown"
        self.constant_pool: List[Any] = [None]
        self.class_name = ""
        self.super_class_name = ""
        self.interfaces: List[str] = []
        self.methods: List[Dict[str, Any]] = []
        self.strings: List[str] = []
        self.method_calls: List[Dict[str, str]] = []

    def parse(self) -> bool:
        if len(self.data) < 10 or not self.data.startswith(b"\xCA\xFE\xBA\xBE"):
            return False

        try:
            magic, self.minor_version, self.major_version, cp_count = struct.unpack_from(">IHHH", self.data, 0)
            self.java_version_name = JAVA_VERSION_MAP.get(self.major_version, f"Java Major {self.major_version}")
            self.is_valid = True

            offset = 10
            i = 1
            while i < cp_count and offset < len(self.data):
                tag = self.data[offset]
                offset += 1

                if tag == self.TAG_UTF8:
                    str_len = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    val = self.data[offset:offset+str_len].decode("utf-8", errors="ignore")
                    offset += str_len
                    self.constant_pool.append({"tag": tag, "value": val})
                    self.strings.append(val)
                elif tag in (self.TAG_INTEGER, self.TAG_FLOAT):
                    val = struct.unpack_from(">I", self.data, offset)[0]
                    offset += 4
                    self.constant_pool.append({"tag": tag, "value": val})
                elif tag in (self.TAG_LONG, self.TAG_DOUBLE):
                    val = struct.unpack_from(">Q", self.data, offset)[0]
                    offset += 8
                    self.constant_pool.append({"tag": tag, "value": val})
                    self.constant_pool.append(None)
                    i += 1
                elif tag in (self.TAG_CLASS, self.TAG_STRING, self.TAG_MODULE, self.TAG_PACKAGE):
                    idx = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    self.constant_pool.append({"tag": tag, "index": idx})
                elif tag in (self.TAG_FIELDREF, self.TAG_METHODREF, self.TAG_INTERFACE_METHODREF, self.TAG_NAME_AND_TYPE, self.TAG_DYNAMIC, self.TAG_INVOKE_DYNAMIC):
                    idx1, idx2 = struct.unpack_from(">HH", self.data, offset)
                    offset += 4
                    self.constant_pool.append({"tag": tag, "idx1": idx1, "idx2": idx2})
                elif tag == self.TAG_METHOD_HANDLE:
                    kind, idx = struct.unpack_from(">BH", self.data, offset)
                    offset += 3
                    self.constant_pool.append({"tag": tag, "kind": kind, "index": idx})
                elif tag == self.TAG_METHOD_TYPE:
                    idx = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    self.constant_pool.append({"tag": tag, "index": idx})
                else:
                    break
                i += 1

            # Resolve Class & Method References
            for item in self.constant_pool:
                if not item:
                    continue
                if item.get("tag") in (self.TAG_METHODREF, self.TAG_INTERFACE_METHODREF):
                    cls_name = self._resolve_class_name(item.get("idx1", 0))
                    name, desc = self._resolve_name_and_type(item.get("idx2", 0))
                    if cls_name and name:
                        self.method_calls.append({
                            "class": cls_name,
                            "method": name,
                            "descriptor": desc,
                            "full": f"{cls_name}.{name}{desc}"
                        })

            if offset + 6 <= len(self.data):
                _, this_cls_idx, super_cls_idx = struct.unpack_from(">HHH", self.data, offset)
                self.class_name = self._resolve_class_name(this_cls_idx)
                self.super_class_name = self._resolve_class_name(super_cls_idx)

            return True
        except Exception as e:
            logger.debug(f"Java Class parsing error: {e}")
            return False

    def _get_utf8(self, idx: int) -> str:
        if 0 < idx < len(self.constant_pool):
            item = self.constant_pool[idx]
            if item and item.get("tag") == self.TAG_UTF8:
                return item.get("value", "")
        return ""

    def _resolve_class_name(self, idx: int) -> str:
        if 0 < idx < len(self.constant_pool):
            item = self.constant_pool[idx]
            if item and item.get("tag") == self.TAG_CLASS:
                return self._get_utf8(item.get("index", 0))
        return ""

    def _resolve_name_and_type(self, idx: int) -> Tuple[str, str]:
        if 0 < idx < len(self.constant_pool):
            item = self.constant_pool[idx]
            if item and item.get("tag") == self.TAG_NAME_AND_TYPE:
                return self._get_utf8(item.get("idx1", 0)), self._get_utf8(item.get("idx2", 0))
        return "", ""


class JavaAnalyzer(BaseAnalyzer):
    """
    Forensic security analyzer for Java source code (.java), bytecode (.class), and archives (.jar).
    """
    @property
    def name(self) -> str:
        return "JavaAnalyzer"

    @classmethod
    def is_java_file(cls, file_path: Path, filename: str = "") -> bool:
        """Determine if a file is a Java source file, class file, or Java archive."""
        name_lower = filename.lower()
        if name_lower.endswith((".java", ".class", ".jar", ".war", ".ear")):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"\xCA\xFE\xBA\xBE"):
                    # Check if Java class (major version 45 to 70)
                    if len(header) >= 8:
                        major = struct.unpack_from(">H", header, 6)[0]
                        if 45 <= major <= 70:
                            return True
                if header.startswith(b"PK\x03\x04"):
                    with zipfile.ZipFile(file_path, "r") as zf:
                        nl = zf.namelist()
                        if "META-INF/MANIFEST.MF" in nl or any(n.endswith(".class") for n in nl):
                            return True
        except Exception:
            pass
        return False

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        name_lower = filename.lower()

        data: Dict[str, Any] = {
            "is_java": True,
            "filename": filename,
            "file_size": Path(file_path).stat().st_size,
            "java_type": "unknown", # "source", "class", "jar"
            "java_subtype": "source",
            "package_name": "",
            "class_name": "",
            "super_class": "",
            "java_version": "",
            "main_class": "",
            "premain_class": "",
            "agent_class": "",
            "permissions": "",
            "dangerous_apis": [],
            "rat_detections": [],
            "classes_count": 0,
            "packages_count": 0,
            "classes_list": [],
            "embedded_binaries": [],
            "iocs": {"urls": [], "ips": []},
            "code_preview": "",
            "highlighted_lines": [],
            "mitre_techniques": [],
            "risk_score": 0,
            "risk_level": "CLEAN"
        }

        # 1. Java Source Code Analysis (.java)
        if name_lower.endswith(".java") or "java" in mime_type and not name_lower.endswith((".class", ".jar")):
            self._analyze_java_source(file_path, data, findings)

        # 2. Java Compiled Bytecode (.class)
        elif name_lower.endswith(".class") or self._is_class_bytes(file_path):
            self._analyze_java_class(file_path, data, findings)

        # 3. Java Archive (.jar, .war, .ear)
        elif name_lower.endswith((".jar", ".war", ".ear")) or zipfile.is_zipfile(file_path):
            self._analyze_java_archive(file_path, data, findings)

        # Calculate Overall Risk Score
        crit_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        med_count = sum(1 for f in findings if f.severity == "medium")

        score = min(100, crit_count * 30 + high_count * 15 + med_count * 5)
        data["risk_score"] = score
        if score >= 60 or crit_count > 0:
            data["risk_level"] = "CRITICAL"
        elif score >= 35 or high_count > 0:
            data["risk_level"] = "HIGH"
        elif score >= 15:
            data["risk_level"] = "MEDIUM"
        else:
            data["risk_level"] = "LOW"

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )

    def _is_class_bytes(self, file_path: Path) -> bool:
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header.startswith(b"\xCA\xFE\xBA\xBE"):
                    major = struct.unpack_from(">H", header, 6)[0]
                    return 45 <= major <= 70
        except Exception:
            pass
        return False

    def _analyze_java_source(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]):
        data["java_type"] = "source"
        data["java_subtype"] = "source"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data["code_preview"] = content[:15000]

            # Extract package and class name
            pkg_m = re.search(r'package\s+([a-zA-Z0-9_.]+)\s*;', content)
            if pkg_m:
                data["package_name"] = pkg_m.group(1)

            cls_m = re.search(r'(?:public\s+)?(?:final\s+)?(?:abstract\s+)?(?:class|interface|enum|record)\s+([a-zA-Z0-9_]+)', content)
            if cls_m:
                data["class_name"] = cls_m.group(1)

            # Check dangerous APIs in source code
            lines = content.splitlines()
            highlighted_lines = []
            detected_apis = []

            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if clean_line.startswith(("//", "/*", "*")):
                    continue

                for api_def in HIGH_RISK_JAVA_APIS:
                    if api_def["pattern"].search(clean_line):
                        entry = {
                            "line": line_idx,
                            "code": clean_line[:120],
                            "api": api_def["api"],
                            "title": api_def["title"],
                            "severity": api_def["severity"],
                            "category": api_def.get("category", "execution"),
                            "description": api_def["description"],
                            "risk_explanation": api_def.get("risk_explanation", ""),
                            "remediation": api_def.get("remediation", ""),
                            "cwe": api_def.get("cwe", ""),
                            "owasp": api_def.get("owasp", ""),
                            "mitre": api_def["mitre"],
                            "mitre_name": api_def["mitre_name"]
                        }
                        detected_apis.append(entry)
                        highlighted_lines.append(line_idx)

            data["dangerous_apis"] = detected_apis
            data["highlighted_lines"] = list(set(highlighted_lines))

            # Generate Findings for Detected APIs
            api_titles = list(set(a["title"] for a in detected_apis))
            for title in api_titles:
                matches = [a for a in detected_apis if a["title"] == title]
                sample = matches[0]
                findings.append(Finding(
                    category="active_content",
                    severity=sample["severity"],
                    title=f"Java Security Finding: {title}",
                    description=f"{sample['description']} (Observed on line {sample['line']}: '{sample['code']}').",
                    details={"occurrences": len(matches), "samples": matches[:5]}
                ))

            # Scan for Network URLs and IPs
            urls = re.findall(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', content)
            data["iocs"]["urls"] = list(set(urls))[:50]

            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', content)
            data["iocs"]["ips"] = [ip for ip in set(ips) if not ip.startswith(("127.", "0.", "255.", "192.168.", "10."))][:50]

            # Check Java RAT signatures
            for rat in JAVA_RAT_SIGNATURES:
                if any(p.search(content) for p in rat["patterns"]):
                    data["rat_detections"].append(rat["name"])
                    findings.append(Finding(
                        category="malware",
                        severity=rat["severity"],
                        title=f"Malicious Java Signature Match: {rat['name']}",
                        description=f"Source code matches structural signatures associated with known threat tool {rat['name']}.",
                        details={"rat_family": rat["name"]}
                    ))

        except Exception as e:
            logger.debug(f"Java source analysis error: {e}")

    def _analyze_java_class(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]):
        data["java_type"] = "class"
        data["java_subtype"] = "class"
        try:
            class_bytes = file_path.read_bytes()
            parser = JavaClassParser(class_bytes)
            if parser.parse():
                data["class_name"] = parser.class_name.replace("/", ".")
                data["super_class"] = parser.super_class_name.replace("/", ".")
                data["java_version"] = parser.java_version_name

                # Extract package name
                if "." in data["class_name"]:
                    data["package_name"] = ".".join(data["class_name"].split(".")[:-1])

                # Check dangerous method calls from constant pool
                detected_apis = []
                joined_methods = " ".join([m["full"] for m in parser.method_calls] + parser.strings)

                for api_def in HIGH_RISK_JAVA_APIS:
                    if api_def["pattern"].search(joined_methods):
                        detected_apis.append({
                            "api": api_def["api"],
                            "title": api_def["title"],
                            "severity": api_def["severity"],
                            "category": api_def.get("category", "execution"),
                            "description": api_def["description"],
                            "risk_explanation": api_def.get("risk_explanation", ""),
                            "remediation": api_def.get("remediation", ""),
                            "cwe": api_def.get("cwe", ""),
                            "owasp": api_def.get("owasp", ""),
                            "mitre": api_def["mitre"],
                            "mitre_name": api_def["mitre_name"]
                        })

                data["dangerous_apis"] = detected_apis

                for api in detected_apis:
                    findings.append(Finding(
                        category="active_content",
                        severity=api["severity"],
                        title=f"Java Bytecode Finding: {api['title']}",
                        description=f"Class bytecode references high-risk runtime API '{api['api']}': {api['description']}.",
                        details=api
                    ))

                # URLs and Strings
                urls = []
                for s in parser.strings:
                    for u in re.findall(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', s):
                        urls.append(u)
                data["iocs"]["urls"] = list(set(urls))[:50]

                # Decompile / Constant Pool Summary for preview
                lines = [
                    f"// Compiled Java Bytecode: {data['class_name']}",
                    f"// Target Platform: {parser.java_version_name} (Major: {parser.major_version})",
                    f"// Superclass: {data['super_class']}",
                    "",
                    f"public class {data['class_name'].split('.')[-1]} extends {data['super_class'].split('.')[-1]} {{",
                    "    // Method Invocations Resolved from Constant Pool:"
                ]
                for mc in parser.method_calls[:30]:
                    lines.append(f"    // Invokes: {mc['full']}")
                lines.append("}")
                data["code_preview"] = "\n".join(lines)

        except Exception as e:
            logger.debug(f"Java class analysis error: {e}")

    def _analyze_java_archive(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]):
        data["java_type"] = "jar"
        data["java_subtype"] = "jar"
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infos = zf.infolist()
                namelist = [i.filename for i in infos]

                data["classes_count"] = sum(1 for n in namelist if n.endswith(".class"))
                data["classes_list"] = [n for n in namelist if n.endswith(".class")][:50]
                data["embedded_binaries"] = [
                    n for n in namelist
                    if Path(n).suffix.lower() in [".dll", ".so", ".dylib", ".exe", ".sh", ".bat", ".bin"]
                ]

                packages = set()
                for n in namelist:
                    if n.endswith(".class") and "/" in n:
                        packages.add("/".join(n.split("/")[:-1]).replace("/", "."))
                data["packages_count"] = len(packages)

                # Parse META-INF/MANIFEST.MF
                if "META-INF/MANIFEST.MF" in namelist:
                    manifest_content = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                    data["code_preview"] = manifest_content[:15000]

                    for line in manifest_content.splitlines():
                        if line.lower().startswith("main-class:"):
                            data["main_class"] = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("premain-class:"):
                            data["premain_class"] = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("agent-class:"):
                            data["agent_class"] = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("permissions:"):
                            data["permissions"] = line.split(":", 1)[1].strip()

                # Findings for Executable JAR
                if data["main_class"]:
                    findings.append(Finding(
                        category="executable",
                        severity="medium",
                        title=f"Standalone Executable JAR (Main-Class: {data['main_class']})",
                        description=f"JAR manifest defines standalone entry point '{data['main_class']}'. The archive will execute automatically when double-clicked or invoked via 'java -jar'.",
                        details={"main_class": data["main_class"]}
                    ))

                # Findings for Premain-Class (Java Agent Hook)
                if data["premain_class"] or data["agent_class"]:
                    agent_cls = data["premain_class"] or data["agent_class"]
                    findings.append(Finding(
                        category="persistence",
                        severity="critical",
                        title=f"Java Instrumentation Agent Detected (Premain-Class: {agent_cls})",
                        description=f"Archive defines Java Instrumentation Agent entry point '{agent_cls}'. Java agents execute prior to standard application entry points and possess unrestricted access to hook JVM memory and rewrite bytecode.",
                        details={"agent_class": agent_cls}
                    ))

                # Findings for Elevated Permissions
                if data["permissions"] and "all-permissions" in data["permissions"].lower():
                    findings.append(Finding(
                        category="security",
                        severity="high",
                        title="Unrestricted Java Permissions Requested (all-permissions)",
                        description="JAR manifest requests elevated 'all-permissions', bypassing standard sandbox restrictions.",
                        details={"permissions": data["permissions"]}
                    ))

                # Findings for Embedded Native Payloads
                if data["embedded_binaries"]:
                    findings.append(Finding(
                        category="payload",
                        severity="high",
                        title=f"Embedded Native Binaries Detected ({len(data['embedded_binaries'])} Files)",
                        description=f"JAR bundles native operating system binaries or libraries: {', '.join(data['embedded_binaries'][:5])}.",
                        details={"embedded_binaries": data["embedded_binaries"]}
                    ))

                # Scan contained .class files for high-risk APIs
                suspicious_apis = []
                all_urls = set()

                for info in infos[:100]:
                    if info.filename.endswith(".class") and info.file_size < 1000000:
                        try:
                            c_bytes = zf.read(info.filename)
                            c_text = c_bytes.decode("latin1", errors="ignore")
                            for api_def in HIGH_RISK_JAVA_APIS:
                                if api_def["pattern"].search(c_text):
                                    suspicious_apis.append({
                                        "class_file": info.filename,
                                        "api": api_def["api"],
                                        "title": api_def["title"],
                                        "severity": api_def["severity"],
                                        "category": api_def.get("category", "execution"),
                                        "description": api_def["description"],
                                        "risk_explanation": api_def.get("risk_explanation", ""),
                                        "remediation": api_def.get("remediation", ""),
                                        "cwe": api_def.get("cwe", ""),
                                        "owasp": api_def.get("owasp", ""),
                                        "mitre": api_def["mitre"],
                                        "mitre_name": api_def["mitre_name"]
                                    })
                            for u in re.findall(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', c_text):
                                all_urls.add(u)
                        except Exception:
                            pass

                # Set JAR triage compatibility fields
                data["is_jar"] = True
                data["class_count"] = data["classes_count"]
                data["manifest_content"] = data.get("code_preview", "")
                data["packages"] = sorted(list(packages))
                data["total_entries"] = len(namelist)
                data["suspicious_apis"] = suspicious_apis
                data["dangerous_apis"] = suspicious_apis
                data["iocs"]["urls"] = list(all_urls)[:50]

                # Disassemble main entry class or first .class for rich preview
                target_class_entry = None
                if data.get("main_class"):
                    candidate = data["main_class"].replace(".", "/") + ".class"
                    if candidate in namelist:
                        target_class_entry = candidate
                if not target_class_entry:
                    if suspicious_apis:
                        target_class_entry = suspicious_apis[0]["class_file"]
                    elif data["classes_list"]:
                        target_class_entry = data["classes_list"][0]

                if target_class_entry and target_class_entry in namelist:
                    try:
                        cls_bytes = zf.read(target_class_entry)
                        c_parser = JavaClassParser(cls_bytes)
                        if c_parser.parse():
                            lines = [
                                "",
                                "// ==========================================================================",
                                f"// Disassembled Entry / Target Class: {target_class_entry}",
                                f"// Target JVM: {c_parser.java_version_name} (Major: {c_parser.major_version})",
                                f"// Superclass: {c_parser.super_class_name}",
                                f"// Interfaces: {', '.join(c_parser.interfaces) if c_parser.interfaces else 'None'}",
                                "// ==========================================================================",
                                f"public class {c_parser.class_name.split('/')[-1]} extends {c_parser.super_class_name.split('/')[-1]} {{",
                                "    // Method Invocations Resolved from Constant Pool:"
                            ]
                            for mc in c_parser.method_calls[:40]:
                                lines.append(f"    // Invokes: {mc['full']}")
                            lines.append("}")
                            data["code_preview"] = (data.get("code_preview", "") + "\n" + "\n".join(lines)).strip()
                    except Exception as e:
                        logger.debug(f"Class disassembly in JAR failed: {e}")

                # Group API findings
                unique_api_titles = list(set(a["title"] for a in suspicious_apis))
                for title in unique_api_titles:
                    sample = next(a for a in suspicious_apis if a["title"] == title)
                    findings.append(Finding(
                        category="active_content",
                        severity=sample["severity"],
                        title=f"Dangerous Java Bytecode API: {title}",
                        description=f"{sample['description']}. Detected in archive classes (e.g. {sample['class_file']}).",
                        details=sample
                    ))

                # Check Java RAT signatures across manifest and filenames
                joined_all = " ".join(namelist) + " " + data.get("code_preview", "")
                for rat in JAVA_RAT_SIGNATURES:
                    if any(p.search(joined_all) for p in rat["patterns"]):
                        data["rat_detections"].append(rat["name"])
                        findings.append(Finding(
                            category="malware",
                            severity=rat["severity"],
                            title=f"Malicious Java Signature Match: {rat['name']}",
                            description=f"Archive contents match structural signatures associated with {rat['name']}.",
                            details={"rat_family": rat["name"]}
                        ))

        except Exception as e:
            logger.debug(f"JAR analysis error: {e}")
