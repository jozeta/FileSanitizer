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
import uuid
from collections import Counter
from datetime import datetime, timezone
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
    },
    {
        "pattern": re.compile(r'java/lang/invoke/MethodHandles|MethodHandles\.lookup', re.I),
        "api": "MethodHandles.lookup()",
        "title": "Dynamic MethodHandles Invocation & Introspection",
        "severity": "medium",
        "category": "reflection",
        "description": "Utilizes polymorphic MethodHandles to invoke methods dynamically, potentially obscuring execution targets from static inspection.",
        "risk_explanation": "Enables low-level reflective invocation that bypasses direct caller-sensitive method dispatch checks, frequently abused to obscure dangerous API calls.",
        "remediation": "Restrict dynamic method handle invocation to well-defined dependency injection frameworks.",
        "cwe": "CWE-470: Use of Externally-Controlled Input to Select Classes or Code",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1626",
        "mitre_name": "Obfuscated Files or Information"
    },
    {
        "pattern": re.compile(r'javax/tools/JavaCompiler|ToolProvider\.getSystemJavaCompiler', re.I),
        "api": "JavaCompiler",
        "title": "Runtime Java Source Code Compilation",
        "severity": "critical",
        "category": "code_loading",
        "description": "Dynamically compiles on-the-fly Java source code in memory during execution.",
        "risk_explanation": "Compiles arbitrary Java source strings directly into executable bytecode at runtime, providing an evasion mechanism to compile malicious payloads on the victim host.",
        "remediation": "Package pre-compiled class files into the build rather than compiling code dynamically at runtime.",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1027.004",
        "mitre_name": "Compile After Delivery"
    },
    {
        "pattern": re.compile(r'Runtime\.getRuntime\(\)\.addShutdownHook|addShutdownHook', re.I),
        "api": "Runtime.addShutdownHook()",
        "title": "Process Shutdown Hook Registration",
        "severity": "medium",
        "category": "persistence",
        "description": "Registers a thread executed automatically when JVM terminates or receives a termination signal.",
        "risk_explanation": "Shutdown hooks execute when the JVM is closing. Malware abuses shutdown hooks for anti-analysis cleanup, persistence installation, or dropping secondary payloads before process termination.",
        "remediation": "Ensure shutdown hooks only perform clean resource disposal (closing connections, saving state).",
        "cwe": "CWE-672: Operation on Resource After Expiration or Release",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1543",
        "mitre_name": "Create or Modify System Process"
    },
    {
        "pattern": re.compile(r'javax/script/ScriptEngine|ScriptEngineManager|ScriptEngine;?\.?eval', re.I),
        "api": "ScriptEngine.eval()",
        "title": "Dynamic Script Engine Execution (Nashorn / JS / Groovy)",
        "severity": "critical",
        "category": "execution",
        "description": "Executes dynamically interpreted script code (JavaScript, Groovy, Python) within the JVM.",
        "risk_explanation": "Allows arbitrary script execution inside the JVM runtime without bytecode compilation, frequently used as an in-memory execution cradle.",
        "remediation": "Validate and sanitize script inputs, or disable JSR-223 ScriptEngineManager unless strictly required.",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059",
        "mitre_name": "Command and Scripting Interpreter"
    },
    {
        "pattern": re.compile(r'javax/el/ExpressionFactory|ValueExpression|MethodExpression', re.I),
        "api": "Expression Language (EL)",
        "title": "Java Expression Language (EL) Dynamic Evaluation",
        "severity": "high",
        "category": "injection",
        "description": "Evaluates dynamic Expression Language strings (JSP / Spring EL / OGNL).",
        "risk_explanation": "Untrusted input in Expression Language strings allows attackers to evaluate Java expressions that invoke Runtime.getRuntime().exec() or access internal objects (Spring4Shell / Struts RCE style).",
        "remediation": "Never concatenate untrusted input into EL expression templates.",
        "cwe": "CWE-917: Expression Language Injection",
        "owasp": "A03:2021-Injection",
        "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application"
    },
    {
        "pattern": re.compile(r'java/sql/Statement;?\.?execute|java/sql/Statement;?\.?executeQuery', re.I),
        "api": "java.sql.Statement.execute()",
        "title": "Raw SQL Statement Execution (SQLi Risk)",
        "severity": "medium",
        "category": "injection",
        "description": "Executes raw SQL query strings directly against relational databases.",
        "risk_explanation": "Using Statement.execute() instead of PreparedStatement invites SQL injection if query parameters are concatenated from user input.",
        "remediation": "Always use java.sql.PreparedStatement with parameterized query placeholders (?).",
        "cwe": "CWE-89: SQL Injection",
        "owasp": "A03:2021-Injection",
        "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application"
    },
    {
        "pattern": re.compile(r'org/apache/commons/exec/CommandLine|DefaultExecutor', re.I),
        "api": "org.apache.commons.exec",
        "title": "Apache Commons Exec Third-Party Command Spawning",
        "severity": "critical",
        "category": "execution",
        "description": "Spawns host operating system processes via the Apache Commons Exec library.",
        "risk_explanation": "Third-party process execution wrapper often used to disguise command execution from simple Runtime.exec checks.",
        "remediation": "Audit commands passed to CommandLine and sanitize all command arguments.",
        "cwe": "CWE-78: OS Command Injection",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059",
        "mitre_name": "Command and Scripting Interpreter"
    },
    {
        "pattern": re.compile(r'java/lang/management/ManagementFactory|com/sun/management', re.I),
        "api": "ManagementFactory (JMX)",
        "title": "JVM Runtime & Environment Introspection (Anti-Analysis / Telemetry)",
        "severity": "low",
        "category": "evasion",
        "description": "Inspects JVM process arguments, memory pools, thread dumps, and operating system properties.",
        "risk_explanation": "Can be utilized by malware to inspect launch flags for debuggers (-agentlib:jdwp) or detect hypervisor environments.",
        "remediation": "Verify whether management bean queries are required for operational monitoring.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1497",
        "mitre_name": "Virtualization/Sandbox Evasion"
    },
    {
        "pattern": re.compile(r'InvokerTransformer|InstantiateTransformer|TemplatesImpl|MethodClosure|BadAttributeValueExpException|PoolBackedDataSourceBase', re.I),
        "api": "Java Deserialization Gadget Marker",
        "title": "Java Deserialization Gadget Chain Component (ysoserial Marker)",
        "severity": "critical",
        "category": "deserialization",
        "description": "Known Java deserialization gadget class identified in bytecode (CommonsCollections, Xalan, Groovy, C3P0).",
        "risk_explanation": "These classes are well-known building blocks of remote code execution gadget chains (ysoserial). If untrusted ObjectInputStream deserialization occurs, these gadgets allow attackers to execute arbitrary commands.",
        "remediation": "Update or remove vulnerable dependency versions (e.g. Commons Collections 3.2.2+ disables InvokerTransformer by default) and apply ObjectInputFilter.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "mitre": "T1203",
        "mitre_name": "Exploitation for Client Execution"
    }
]

# Java RAT / Malware Signatures
JAVA_RAT_SIGNATURES = [
    {
        "name": "STRRAT Java RAT / Crimson Infostealer (SecurityScorecard Case Study)",
        "patterns": [
            re.compile(r'ALLATORIxDEMO', re.I),
            re.compile(r'\.crimson\b', re.I),
            re.compile(r'lock\.file|[\d]+lock\.file', re.I),
            re.compile(r'strrat|str_rat', re.I),
        ],
        "severity": "critical"
    },
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
        self.fields: List[Dict[str, Any]] = []
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
                offset += 6

                # Interfaces
                if offset + 2 <= len(self.data):
                    interfaces_count = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    for _ in range(interfaces_count):
                        if offset + 2 <= len(self.data):
                            iface_idx = struct.unpack_from(">H", self.data, offset)[0]
                            offset += 2
                            iface_name = self._resolve_class_name(iface_idx)
                            if iface_name:
                                self.interfaces.append(iface_name)

                # Fields
                if offset + 2 <= len(self.data):
                    fields_count = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    for _ in range(fields_count):
                        if offset + 8 > len(self.data):
                            break
                        f_flags, f_name_idx, f_desc_idx, f_attr_count = struct.unpack_from(">HHHH", self.data, offset)
                        offset += 8
                        f_name = self._get_utf8(f_name_idx)
                        f_desc = self._get_utf8(f_desc_idx)
                        if f_name:
                            self.fields.append({
                                "name": f_name,
                                "descriptor": f_desc,
                                "flags": f_flags,
                                "type": self._parse_descriptor_type(f_desc),
                                "formatted": f"{self._format_flags(f_flags)} {self._parse_descriptor_type(f_desc)} {f_name}".strip()
                            })
                        for _ in range(f_attr_count):
                            if offset + 6 > len(self.data):
                                break
                            _, attr_len = struct.unpack_from(">HI", self.data, offset)
                            offset += 6 + attr_len

                # Methods
                if offset + 2 <= len(self.data):
                    methods_count = struct.unpack_from(">H", self.data, offset)[0]
                    offset += 2
                    for _ in range(methods_count):
                        if offset + 8 > len(self.data):
                            break
                        m_flags, m_name_idx, m_desc_idx, m_attr_count = struct.unpack_from(">HHHH", self.data, offset)
                        offset += 8
                        m_name = self._get_utf8(m_name_idx)
                        m_desc = self._get_utf8(m_desc_idx)
                        if m_name:
                            sig = self._format_method_signature(m_name, m_desc, m_flags)
                            self.methods.append({
                                "name": m_name,
                                "descriptor": m_desc,
                                "flags": m_flags,
                                "signature": sig,
                                "is_static": bool(m_flags & 0x0008),
                                "is_native": bool(m_flags & 0x0100),
                                "is_main": (m_name == "main" and "([Ljava/lang/String;)V" in m_desc and bool(m_flags & 0x0008))
                            })
                        for _ in range(m_attr_count):
                            if offset + 6 > len(self.data):
                                break
                            _, attr_len = struct.unpack_from(">HI", self.data, offset)
                            offset += 6 + attr_len

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

    @staticmethod
    def _format_flags(flags: int) -> str:
        parts = []
        if flags & 0x0001: parts.append("public")
        elif flags & 0x0002: parts.append("private")
        elif flags & 0x0004: parts.append("protected")
        if flags & 0x0008: parts.append("static")
        if flags & 0x0010: parts.append("final")
        if flags & 0x0020: parts.append("synchronized")
        if flags & 0x0040: parts.append("volatile")
        if flags & 0x0080: parts.append("transient")
        if flags & 0x0100: parts.append("native")
        if flags & 0x0400: parts.append("abstract")
        return " ".join(parts)

    @classmethod
    def _parse_descriptor_type(cls, desc: str) -> str:
        if not desc:
            return "void"
        dim = 0
        while desc.startswith("["):
            dim += 1
            desc = desc[1:]
        base = "Object"
        if desc == "V": base = "void"
        elif desc == "Z": base = "boolean"
        elif desc == "B": base = "byte"
        elif desc == "C": base = "char"
        elif desc == "S": base = "short"
        elif desc == "I": base = "int"
        elif desc == "J": base = "long"
        elif desc == "F": base = "float"
        elif desc == "D": base = "double"
        elif desc.startswith("L") and desc.endswith(";"):
            cname = desc[1:-1].replace("/", ".")
            base = cname.split(".")[-1]
        return base + ("[]" * dim)

    @classmethod
    def _format_method_signature(cls, name: str, desc: str, flags: int) -> str:
        prefix = cls._format_flags(flags)
        if not desc or "(" not in desc or ")" not in desc:
            return f"{prefix} {name}()".strip()
        params_str = desc[desc.find("(")+1:desc.find(")")]
        ret_str = desc[desc.find(")")+1:]
        ret_type = cls._parse_descriptor_type(ret_str)

        params = []
        p_idx = 0
        while p_idx < len(params_str):
            dim = 0
            while p_idx < len(params_str) and params_str[p_idx] == "[":
                dim += 1
                p_idx += 1
            if p_idx >= len(params_str):
                break
            ch = params_str[p_idx]
            if ch in "ZBCSIJFD":
                p_type = cls._parse_descriptor_type(ch) + ("[]" * dim)
                params.append(p_type)
                p_idx += 1
            elif ch == "L":
                semi = params_str.find(";", p_idx)
                if semi != -1:
                    raw_c = params_str[p_idx+1:semi].replace("/", ".")
                    params.append(raw_c.split(".")[-1] + ("[]" * dim))
                    p_idx = semi + 1
                else:
                    break
            else:
                p_idx += 1

        arg_list = ", ".join(params)
        if name == "<init>":
            return f"{prefix} <init>({arg_list})".strip()
        if name == "<clinit>":
            return "static <clinit>()"
        return f"{prefix} {ret_type} {name}({arg_list})".strip()

    def get_decompiled_source(self, dangerous_apis: Optional[List[Dict[str, Any]]] = None) -> str:
        full_cls = (self.class_name or "AnonymousClass").replace("/", ".")
        pkg = ".".join(full_cls.split(".")[:-1]) if "." in full_cls else ""
        simple = full_cls.split(".")[-1] if full_cls else "AnonymousClass"
        super_simple = self.super_class_name.replace("/", ".").split(".")[-1] if self.super_class_name else "Object"
        ifaces = [i.replace("/", ".").split(".")[-1] for i in self.interfaces]

        slash_cls = (self.class_name or "AnonymousClass").replace(".", "/")
        lines = [
            f"// ==========================================================================",
            f"// Disassembled Entry / Target Class: {slash_cls}.class",
            f"// Decompiled Java Bytecode: {full_cls}",
            f"// Target Platform: {self.java_version_name} (Major: {self.major_version})",
            f"// Superclass: {self.super_class_name.replace('/', '.')}",
            f"// Interfaces: {', '.join([i.replace('/', '.') for i in self.interfaces]) if self.interfaces else 'None'}",
            f"// Constant Pool Symbols: {len(self.constant_pool)} entries | Methods: {len(self.methods)}",
            f"// ==========================================================================",
            ""
        ]
        if pkg:
            lines.append(f"package {pkg};\n")

        header = f"public class {simple}"
        if super_simple:
            header += f" extends {super_simple}"
        if ifaces:
            header += f" implements {', '.join(ifaces)}"
        header += " {"
        lines.append(header)

        if self.fields:
            lines.append("    // --- Fields ---")
            for f in self.fields:
                lines.append(f"    {f.get('formatted', f.get('name'))};")
            lines.append("")

        if self.methods:
            lines.append("    // --- Methods ---")
            for m in self.methods:
                lines.append(f"    {m.get('signature', m.get('name') + '()')};")
            lines.append("")

        if self.method_calls:
            lines.append("    // --- Invocations & Resolved Constant Pool References ---")
            seen_mc = set()
            for mc in self.method_calls[:40]:
                sig = f"{mc.get('class', '').replace('/', '.')}.{mc.get('method', '')}{mc.get('descriptor', '')}"
                if sig not in seen_mc:
                    seen_mc.add(sig)
                    lines.append(f"    // invokes: {sig}")
            if len(self.method_calls) > 40:
                lines.append(f"    // ... and {len(self.method_calls) - 40} additional method references")
            lines.append("")

        if dangerous_apis:
            lines.append("    // --- ⚠️ Security Findings & High-Risk APIs ---")
            for d in dangerous_apis:
                lines.append(f"    // [{d.get('severity', 'HIGH').upper()}] {d.get('title', d.get('api'))} ({d.get('api')})")
            lines.append("")

        lines.append("}")
        return "\n".join(lines)


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

    def analyze(self, file_path: Path, filename: str, mime_type: str, disabled_checks: Optional[List[str]] = None) -> AnalyzerResult:
        if disabled_checks is None:
            disabled_checks = []
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
            "risk_level": "CLEAN",
            "behavioral_analysis": None,
            "strrat_profile": None,
            "archive_security": None,
            "dependencies": [],
            "shaded_libraries": [],
            "cve_advisories": [],
            "cyclonedx_sbom": None,
            "secrets_and_ctf": None
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

        # Suppress data and findings for disabled checks
        if "check_bytecode_dangerous_apis" in disabled_checks:
            data["dangerous_apis"] = []
            findings[:] = [f for f in findings if not any(k in f.title.lower() for k in ("dangerous api", "command execution", "shell command", "reflection", "jndi", "crypto", "ecb"))]
        if "check_embedded_binaries" in disabled_checks:
            data["embedded_binaries"] = []
            findings[:] = [f for f in findings if not any(k in f.title.lower() for k in ("embedded native", "embedded binaries", "dll", "so", "exe"))]
        if "check_java_rat_signatures" in disabled_checks:
            data["rat_detections"] = []
            data["behavioral_analysis"] = None
            data["strrat_profile"] = None
            findings[:] = [f for f in findings if not any(k in f.title.lower() for k in ("rat", "strrat", "behavioral", "pillar", "ransomware", "credential harvesting", "persistence"))]
        if "check_manifest_entrypoint" in disabled_checks:
            data["main_class"] = ""
            data["premain_class"] = ""
            data["agent_class"] = ""
            findings[:] = [f for f in findings if not any(k in f.title.lower() for k in ("main-class", "premain-class", "agent-class"))]

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

    def _audit_behavioral_capabilities(
        self,
        strings: List[str],
        method_calls: List[Dict[str, str]],
        class_names: List[str],
        namelist: List[str],
        manifest_text: str,
        embedded_binaries: List[str],
        raw_text_corpus: str,
        iocs: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Conducts deep behavioral forensic audit across 4 core pillars based on SecurityScorecard's
        'How to Analyze Java Malware – A Case Study of STRRAT':
        1. 🌐 Internet activity (Can this JAR contact external servers?)
        2. 📂 File access (Can this JAR read, collect, or package files?)
        3. 🛠 System command execution (Can this JAR run OS-level commands?)
        4. 🧩 Hidden or hard-to-review code (Is the code unusually hard to inspect?)
        """
        # =========================================================================
        # 1. 🌐 INTERNET ACTIVITY
        # =========================================================================
        internet_caps = []
        raw_socket_evidence = []
        for m in method_calls:
            cls = m.get("class", "")
            if any(s in cls for s in ["java/net/Socket", "java/net/ServerSocket", "java/net/DatagramSocket", "java/nio/channels/SocketChannel", "java/nio/channels/ServerSocketChannel"]):
                raw_socket_evidence.append(f"{cls.replace('/', '.')}.{m.get('method', '')}")
        if not raw_socket_evidence and re.search(r'java/net/(?:Server)?Socket|SocketChannel|DatagramSocket', raw_text_corpus):
            raw_socket_evidence.append("java.net.Socket / ServerSocket raw network socket references")

        if raw_socket_evidence:
            internet_caps.append({
                "id": "raw_sockets",
                "name": "Raw Socket Connections",
                "category": "internet",
                "description": "Opens raw low-level TCP/IP or UDP sockets (e.g. for custom C2 protocols, reverse shells, or SOCKS proxying).",
                "severity": "high",
                "evidence": list(set(raw_socket_evidence))[:5]
            })

        http_evidence = []
        for m in method_calls:
            cls = m.get("class", "")
            if any(h in cls for h in ["java/net/HttpURLConnection", "javax/net/ssl/HttpsURLConnection", "java/net/http/HttpClient", "okhttp3", "org/apache/http"]):
                http_evidence.append(f"{cls.replace('/', '.')}.{m.get('method', '')}")
        if not http_evidence and re.search(r'HttpURLConnection|HttpsURLConnection|HttpClient|okhttp3|apache/http', raw_text_corpus):
            http_evidence.append("HTTP/HTTPS Client APIs (HttpURLConnection / HttpClient / OkHttp)")

        if http_evidence:
            internet_caps.append({
                "id": "http_requests",
                "name": "HTTP / Web Client Requests",
                "category": "internet",
                "description": "Transmits HTTP/HTTPS requests to remote servers (telemetry, API log uploads, or command polling).",
                "severity": "medium",
                "evidence": list(set(http_evidence))[:5]
            })

        downloader_evidence = []
        for m in method_calls:
            cls = m.get("class", "")
            mth = m.get("method", "")
            if "URLClassLoader" in cls or "defineClass" in mth:
                downloader_evidence.append(f"{cls.replace('/', '.')}.{mth}")
        if not downloader_evidence and re.search(r'URLClassLoader|ClassLoader\.defineClass', raw_text_corpus):
            downloader_evidence.append("URLClassLoader remote class loader reference")

        if downloader_evidence:
            internet_caps.append({
                "id": "payload_downloader",
                "name": "Remote Code / Payload Downloader",
                "category": "internet",
                "description": "Dynamically fetches and executes extra content or Java bytecode from remote URLs (stager behavior).",
                "severity": "critical",
                "evidence": list(set(downloader_evidence))[:5]
            })

        socks_evidence = []
        if re.search(r'\bsocks(?:5|\b)|proxy_port|SocksSocket|reverse.*proxy', raw_text_corpus, re.I):
            socks_evidence.append("Reverse SOCKS proxy / port redirection strings detected")

        if socks_evidence:
            internet_caps.append({
                "id": "socks_proxy",
                "name": "Reverse SOCKS Proxy & Tunneling",
                "category": "internet",
                "description": "Implements SOCKS proxy tunneling to relay arbitrary threat actor network traffic through the victim.",
                "severity": "high",
                "evidence": socks_evidence[:5]
            })

        endpoint_evidence = []
        urls = iocs.get("urls", [])
        ips = iocs.get("ips", [])
        if urls or ips:
            endpoint_evidence.extend(urls[:5])
            endpoint_evidence.extend([f"IP: {ip}" for ip in ips[:3]])
        if re.search(r'discord\.com/api/webhooks|api\.telegram\.org|pastebin\.com|ngrok\.io|duckdns\.org|checkip|icanhazip', raw_text_corpus, re.I):
            endpoint_evidence.append("External webhook / dynamic DNS / IP lookup C2 infrastructure")

        if endpoint_evidence:
            internet_caps.append({
                "id": "c2_telemetry_endpoints",
                "name": "Hardcoded Network Endpoints & Telemetry",
                "category": "internet",
                "description": "Hardcoded external IP addresses, domain names, or webhook URLs embedded in bytecode/strings.",
                "severity": "high" if any(x in str(endpoint_evidence).lower() for x in ["webhook", "pastebin", "ngrok", "duckdns"]) else "medium",
                "evidence": endpoint_evidence[:5]
            })

        int_score = 0
        if any(c["id"] == "payload_downloader" for c in internet_caps):
            int_score += 40
        if any(c["id"] == "raw_sockets" for c in internet_caps):
            int_score += 35
        if any(c["id"] == "socks_proxy" for c in internet_caps):
            int_score += 30
        if any(c["id"] == "c2_telemetry_endpoints" for c in internet_caps):
            int_score += 25
        if any(c["id"] == "http_requests" for c in internet_caps):
            int_score += 20
        int_score = min(100, int_score)

        if int_score >= 60:
            int_verdict = "SUSPICIOUS"
            int_summary = "Can contact external servers via raw sockets, proxies, or remote code loaders."
        elif int_score >= 20:
            int_verdict = "POTENTIAL"
            int_summary = "Standard network capabilities detected (HTTP/HTTPS client requests or remote endpoints)."
        else:
            int_verdict = "CLEAN"
            int_summary = "No outbound network activity or external communication capabilities identified."

        internet_activity = {
            "detected": len(internet_caps) > 0,
            "score": int_score,
            "verdict": int_verdict,
            "summary": int_summary,
            "capabilities": internet_caps,
            "endpoints": list(set(urls + ips))[:25]
        }

        # =========================================================================
        # 2. 📂 FILE ACCESS
        # =========================================================================
        file_caps = []
        targeted_paths = []

        traversal_evidence = []
        for m in method_calls:
            full = m.get("full", "")
            if any(t in full for t in ["File.listFiles", "File.listRoots", "Files.walkFileTree", "Files.walk", "Files.find", "DirectoryStream"]):
                traversal_evidence.append(full)
        if not traversal_evidence and re.search(r'listFiles|listRoots|walkFileTree|DirectoryStream', raw_text_corpus):
            traversal_evidence.append("Directory traversal APIs (File.listFiles / Files.walkFileTree)")

        if traversal_evidence:
            file_caps.append({
                "id": "filesystem_traversal",
                "name": "Broad Filesystem Traversal & Directory Scanning",
                "category": "file",
                "description": "Recursively scans filesystem directories to enumerate user files, documents, and configurations.",
                "severity": "medium",
                "evidence": list(set(traversal_evidence))[:5]
            })

        sensitive_evidence = []
        for s in strings:
            if isinstance(s, str) and any(k in s for k in ["user.home", "user.dir", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "ALLUSERSPROFILE", "PROGRAMDATA"]):
                sensitive_evidence.append(s)
                targeted_paths.append(s)
        if not sensitive_evidence and re.search(r'user\.home|APPDATA|LOCALAPPDATA|USERPROFILE', raw_text_corpus):
            sensitive_evidence.append("System.getProperty('user.home') or %APPDATA% reference")
            targeted_paths.append("%USERPROFILE% / %APPDATA%")

        if sensitive_evidence:
            file_caps.append({
                "id": "sensitive_folders",
                "name": "Access Outside Normal Application Folders",
                "category": "file",
                "description": "Accesses user profile directories, Desktop, Documents, or AppData outside normal workspace bounds.",
                "severity": "high",
                "evidence": list(set(sensitive_evidence))[:5]
            })

        cred_evidence = []
        cred_patterns = [
            (r'Login Data', "Chrome/Chromium password store ('Login Data')"),
            (r'key[34]\.db', "Firefox NSS database ('key4.db')"),
            (r'logins\.json', "Firefox stored credentials ('logins.json')"),
            (r'cookies\.sqlite', "Browser cookies vault ('cookies.sqlite')"),
            (r'places\.sqlite', "Browser history store ('places.sqlite')"),
            (r'Thunderbird', "Thunderbird email client profiles"),
            (r'webcredentials', "Windows WebCredentials vault"),
            (r'Windows Messaging Subsystem', "Outlook account profile credentials")
        ]
        for pat, desc in cred_patterns:
            if re.search(pat, raw_text_corpus, re.I):
                cred_evidence.append(desc)
                targeted_paths.append(desc)

        if cred_evidence:
            file_caps.append({
                "id": "credential_harvesting",
                "name": "Browser & Credential Vault Harvesting",
                "category": "file",
                "description": "Explicitly targets saved passwords, session cookies, and profile stores for Chrome, Firefox, Edge, or email clients.",
                "severity": "critical",
                "evidence": list(set(cred_evidence))[:5]
            })

        archive_evidence = []
        for m in method_calls:
            cls = m.get("class", "")
            if any(z in cls for z in ["ZipOutputStream", "JarOutputStream", "GZIPOutputStream"]):
                archive_evidence.append(f"{cls.replace('/', '.')}.{m.get('method', '')}")
        if not archive_evidence and re.search(r'ZipOutputStream|JarOutputStream', raw_text_corpus):
            archive_evidence.append("ZipOutputStream archive creation for file staging")

        if archive_evidence:
            file_caps.append({
                "id": "archive_packaging",
                "name": "Packaging Files for Export (ZIP/Archive)",
                "category": "file",
                "description": "Compresses gathered files or logs into ZIP archives for staging and exfiltration.",
                "severity": "medium",
                "evidence": list(set(archive_evidence))[:5]
            })

        ransom_evidence = []
        if re.search(r'\.crimson\b', raw_text_corpus, re.I):
            ransom_evidence.append("STRRAT fake ransomware extension ('.crimson')")
            targeted_paths.append("Victim files appended with .crimson extension")
        if re.search(r'File\.renameTo|Files\.move', raw_text_corpus):
            ransom_evidence.append("Mass file renaming method (File.renameTo)")
        if re.search(r'RESTORE_FILES|README.*DECRYPT|HOW_TO_RECOVER', raw_text_corpus, re.I):
            ransom_evidence.append("Ransom note extortion text")

        if ransom_evidence:
            file_caps.append({
                "id": "ransomware_simulation",
                "name": "Ransomware Simulation & File Extortion (.crimson)",
                "category": "file",
                "description": "Appends ransomware extensions (.crimson) or renames files across directories to simulate extortion.",
                "severity": "critical",
                "evidence": list(set(ransom_evidence))[:5]
            })

        dropper_evidence = []
        if re.search(r'[\d]*lock\.file', raw_text_corpus, re.I):
            dropper_evidence.append("STRRAT instance lockfile ('lock.file')")
        if any(b.lower().endswith(('.vbs', '.bat', '.ps1', '.sh', '.exe', '.dll')) for b in embedded_binaries):
            dropper_evidence.append(f"Bundled executable/script: {', '.join(embedded_binaries[:3])}")
        for m in method_calls:
            cls = m.get("class", "")
            full = m.get("full", "")
            if "FileOutputStream" in cls or "Files.write" in full:
                dropper_evidence.append(f"{cls.replace('/', '.')}.{m.get('method', '')}")
                break

        if dropper_evidence:
            file_caps.append({
                "id": "file_dropper_lockfile",
                "name": "Payload Dropper & Lockfile Mutex",
                "category": "file",
                "description": "Drops secondary executable script files (.bat, .vbs) to disk and checks mutex lockfiles.",
                "severity": "high" if any("lock.file" in e for e in dropper_evidence) else "medium",
                "evidence": list(set(dropper_evidence))[:5]
            })

        file_score = 0
        if any(c["id"] == "credential_harvesting" for c in file_caps):
            file_score += 45
        if any(c["id"] == "ransomware_simulation" for c in file_caps):
            file_score += 40
        if any(c["id"] == "sensitive_folders" for c in file_caps):
            file_score += 25
        if any(c["id"] == "filesystem_traversal" for c in file_caps):
            file_score += 20
        if any(c["id"] == "archive_packaging" for c in file_caps):
            file_score += 20
        if any(c["id"] == "file_dropper_lockfile" for c in file_caps):
            file_score += 20
        file_score = min(100, file_score)

        if file_score >= 60:
            file_verdict = "SUSPICIOUS"
            file_summary = "Can scan filesystem, access user home/AppData, and harvest browser credential stores."
        elif file_score >= 20:
            file_verdict = "POTENTIAL"
            file_summary = "Standard file access capabilities detected (reading configs or compressing archives)."
        else:
            file_verdict = "CLEAN"
            file_summary = "No suspicious filesystem traversal, credential access, or file modification identified."

        file_access = {
            "detected": len(file_caps) > 0,
            "score": file_score,
            "verdict": file_verdict,
            "summary": file_summary,
            "capabilities": file_caps,
            "targeted_paths": list(set(targeted_paths))[:20]
        }

        # =========================================================================
        # 3. 🛠 SYSTEM COMMAND EXECUTION
        # =========================================================================
        cmd_caps = []
        detected_commands = []

        exec_evidence = []
        for m in method_calls:
            full = m.get("full", "")
            if any(e in full for e in ["Runtime.exec", "ProcessBuilder.start", "ProcessBuilder.<init>"]):
                exec_evidence.append(full)
        if not exec_evidence and re.search(r'Runtime(?:\.getRuntime\(\))?\.exec|ProcessBuilder', raw_text_corpus):
            exec_evidence.append("Runtime.getRuntime().exec() / ProcessBuilder process spawning APIs")

        if exec_evidence:
            cmd_caps.append({
                "id": "process_spawning",
                "name": "Host Operating System Process Execution",
                "category": "command",
                "description": "Executes operating system processes via Runtime.exec() or ProcessBuilder.",
                "severity": "critical",
                "evidence": list(set(exec_evidence))[:5]
            })

        shell_evidence = []
        shell_patterns = [
            r'cmd(?:\.exe)?\s+/c', r'powershell(?:\.exe)?\b.*?(?:-enc|-executionpolicy|-nop|\.ps1)',
            r'/bin/(?:ba)?sh\s+-c', r'wscript(?:\.exe)?', r'cscript(?:\.exe)?', r'mshta(?:\.exe)?'
        ]
        for pat in shell_patterns:
            matches = re.findall(pat, raw_text_corpus, re.I)
            if matches:
                shell_evidence.append(f"Command shell invocation: '{matches[0]}'")
                detected_commands.extend(matches[:3])

        for s in strings:
            if isinstance(s, str) and len(s) > 4 and any(c in s.lower() for c in ["cmd.exe", "powershell", "/bin/sh", "/bin/bash"]):
                detected_commands.append(s[:120])

        if shell_evidence:
            cmd_caps.append({
                "id": "command_shells",
                "name": "Command Shell Interpreters (cmd.exe / PowerShell / bash)",
                "category": "command",
                "description": "Launches Windows cmd.exe, PowerShell, or UNIX bash to execute arbitrary shell scripts.",
                "severity": "critical",
                "evidence": list(set(shell_evidence))[:5]
            })

        admin_evidence = []
        admin_patterns = [
            (r'schtasks(?:\.exe)?\s+(?:/create|/run|/delete)', "Windows Task Scheduler persistence (schtasks.exe)"),
            (r'CurrentVersion\\Run', "Windows Registry Run key autostart persistence"),
            (r'sc(?:\.exe)?\s+create', "Windows Service installation (sc.exe)"),
            (r'netsh\s+advfirewall', "Windows Firewall rule modification (netsh)"),
            (r'vssadmin\s+delete\s+shadows', "Shadow copy deletion (anti-recovery)"),
            (r'taskkill\s+/f', "Process termination (taskkill)"),
            (r'attrib\s+\+h', "File attribute hiding (attrib +h)")
        ]
        for pat, desc in admin_patterns:
            if re.search(pat, raw_text_corpus, re.I):
                admin_evidence.append(desc)
                detected_commands.append(desc)

        if admin_evidence:
            cmd_caps.append({
                "id": "system_persistence_admin",
                "name": "Persistence & System Administration Utilities",
                "category": "command",
                "description": "Configures scheduled tasks (schtasks) or Windows Registry Run keys for persistent reboot survival.",
                "severity": "critical",
                "evidence": list(set(admin_evidence))[:5]
            })

        script_evidence = []
        if re.search(r'\.(?:bat|vbs|ps1|sh)\b', raw_text_corpus, re.I) and (exec_evidence or shell_evidence):
            script_evidence.append("Launches external script interpreter (.bat / .vbs / .ps1 / .sh)")

        if script_evidence:
            cmd_caps.append({
                "id": "script_launching",
                "name": "Launching Dropped Secondary Scripts",
                "category": "command",
                "description": "Invokes dropped secondary scripts (.bat, .vbs, .ps1) through the host command interpreter.",
                "severity": "high",
                "evidence": script_evidence[:5]
            })

        cmd_score = 0
        if any(c["id"] == "process_spawning" for c in cmd_caps):
            cmd_score += 40
        if any(c["id"] == "system_persistence_admin" for c in cmd_caps):
            cmd_score += 35
        if any(c["id"] == "command_shells" for c in cmd_caps):
            cmd_score += 35
        if any(c["id"] == "script_launching" for c in cmd_caps):
            cmd_score += 25
        cmd_score = min(100, cmd_score)

        if cmd_score >= 60:
            cmd_verdict = "SUSPICIOUS"
            cmd_summary = "Can run OS-level commands, spawn cmd.exe/PowerShell, and schedule persistence."
        elif cmd_score >= 20:
            cmd_verdict = "POTENTIAL"
            cmd_summary = "Host process invocation or administrative commands detected."
        else:
            cmd_verdict = "CLEAN"
            cmd_summary = "No operating system command execution or shell launching detected."

        command_execution = {
            "detected": len(cmd_caps) > 0,
            "score": cmd_score,
            "verdict": cmd_verdict,
            "summary": cmd_summary,
            "capabilities": cmd_caps,
            "detected_commands": list(set(detected_commands))[:20]
        }

        # =========================================================================
        # 4. 🧩 HIDDEN OR HARD-TO-REVIEW CODE
        # =========================================================================
        obfuscators = []
        indicators = []

        has_allatori = False
        if "ALLATORIxDEMO" in raw_text_corpus or any(isinstance(s, str) and "ALLATORIxDEMO" in s for s in strings):
            has_allatori = True
            obfuscators.append("Allatori Java Obfuscator (Watermark Confirmed)")
            indicators.append({
                "type": "watermark",
                "name": "Allatori Obfuscator Watermark (ALLATORIxDEMO)",
                "severity": "high",
                "detail": "Observed 'ALLATORIxDEMO' constant pool identifier, confirming Allatori protection."
            })

        if re.search(r'_cls|_mth|Zelix|KlassMaster', raw_text_corpus, re.I):
            obfuscators.append("Zelix KlassMaster (ZKM)")
            indicators.append({
                "type": "watermark",
                "name": "Zelix KlassMaster Obfuscation Markers",
                "severity": "high",
                "detail": "Bytecode identifiers and flow flattening match Zelix KlassMaster patterns."
            })

        if re.search(r'PreEmptive|DashO', raw_text_corpus, re.I):
            obfuscators.append("PreEmptive DashO")

        total_classes = len(class_names)
        obfuscated_classes = 0
        for cn in class_names:
            simple_name = cn.split("/")[-1].replace(".class", "")
            if len(simple_name) <= 2 or (simple_name.islower() and len(simple_name) <= 3) or not simple_name.isalnum():
                obfuscated_classes += 1

        ratio = (obfuscated_classes / total_classes) if total_classes > 0 else 0.0
        if ratio >= 0.40 and total_classes >= 3:
            if "ProGuard / Bytecode Collapser" not in obfuscators:
                obfuscators.append("ProGuard / Bytecode Collapser")
            indicators.append({
                "type": "class_structure",
                "name": "Collapsed Obfuscated Class Hierarchy",
                "severity": "high",
                "detail": f"{int(ratio * 100)}% of classes ({obfuscated_classes}/{total_classes}) use short/single-letter identifiers (e.g. a.class, b.class)."
            })

        has_string_decrypter = False
        for s in strings:
            if isinstance(s, str) and s in ["(Ljava/lang/String;)Ljava/lang/String;", "(Ljava/lang/String;I)Ljava/lang/String;"]:
                has_string_decrypter = True
                break
        if not has_string_decrypter and re.search(r'\(Ljava/lang/String;\)Ljava/lang/String;', raw_text_corpus):
            has_string_decrypter = True

        if has_string_decrypter or has_allatori:
            indicators.append({
                "type": "string_encryption",
                "name": "Encrypted Strings & Decryption Routines",
                "severity": "high",
                "detail": "Contains specialized string decryptor method signatures (Ljava/lang/String;)Ljava/lang/String; and multi-byte XOR loops used by Allatori/STRRAT to hide URLs and commands."
            })

        reflection_evidence = []
        for m in method_calls:
            full = m.get("full", "")
            if any(r in full for r in ["Class.forName", "Method.invoke", "Field.get", "sun.misc.Unsafe"]):
                reflection_evidence.append(full)
        if not reflection_evidence and re.search(r'Class\.forName|Method\.invoke|sun/misc/Unsafe', raw_text_corpus):
            reflection_evidence.append("Class.forName / Method.invoke dynamic reflection")

        if reflection_evidence:
            indicators.append({
                "type": "reflection",
                "name": "Dynamic Reflection & Obfuscated Method Resolution",
                "severity": "medium",
                "detail": "Uses Class.forName and Method.invoke to obscure runtime method dispatch from static decompilers."
            })

        if re.search(r'getResourceAsStream', raw_text_corpus):
            indicators.append({
                "type": "hidden_resources",
                "name": "Hidden Bytecode & Streamed Resource Loading",
                "severity": "high",
                "detail": "Invokes getResourceAsStream to dynamically load embedded classes, encrypted payloads, or stubs."
            })

        obf_score = 0
        if has_allatori:
            obf_score += 40
        if ratio >= 0.40 and total_classes >= 3:
            obf_score += 30
        if has_string_decrypter:
            obf_score += 30
        if reflection_evidence:
            obf_score += 20
        if any(i["type"] == "hidden_resources" for i in indicators):
            obf_score += 20
        obf_score = min(100, obf_score)

        is_obfuscated = obf_score >= 35 or len(obfuscators) > 0
        if obf_score >= 50:
            obf_verdict = "OBFUSCATED"
            obf_summary = f"Code is heavily obfuscated ({', '.join(obfuscators) if obfuscators else 'Proprietary'}); exhibits string encryption and collapsed classes."
        elif obf_score >= 25:
            obf_verdict = "SUSPICIOUS"
            obf_summary = "Contains evasion indicators such as dynamic reflection or packed resources."
        else:
            obf_verdict = "CLEAN"
            obf_summary = "Bytecode exhibits standard transparent class names and readable method signatures."

        # STRRAT Heuristic Profile
        strrat_matches = []
        if has_allatori:
            strrat_matches.append("Allatori Java Obfuscator watermark (ALLATORIxDEMO)")
        if re.search(r'\.crimson\b', raw_text_corpus, re.I):
            strrat_matches.append("Fake ransomware extension marker ('.crimson')")
        if re.search(r'[\d]*lock\.file', raw_text_corpus, re.I):
            strrat_matches.append("Instance exclusivity lockfile ('lock.file')")
        if cred_evidence:
            strrat_matches.append(f"Browser/Email SQLite credential store access ({len(cred_evidence)} patterns)")
        if admin_evidence or re.search(r'schtasks|CurrentVersion\\Run', raw_text_corpus, re.I):
            strrat_matches.append("Windows Task Scheduler / Registry Run key persistence")
        if raw_socket_evidence or socks_evidence:
            strrat_matches.append("Raw TCP socket communication / SOCKS reverse proxy")
        if shell_evidence or exec_evidence:
            strrat_matches.append("Operating system shell command execution (cmd.exe / PowerShell)")

        is_strrat_candidate = False
        strrat_confidence = "NONE"
        if len(strrat_matches) >= 3 or (has_allatori and (re.search(r'\.crimson', raw_text_corpus) or re.search(r'lock\.file', raw_text_corpus) or cred_evidence)):
            is_strrat_candidate = True
            if len(strrat_matches) >= 4 or (has_allatori and re.search(r'\.crimson', raw_text_corpus)):
                strrat_confidence = "HIGH"
            else:
                strrat_confidence = "MEDIUM"
        elif len(strrat_matches) >= 2:
            is_strrat_candidate = True
            strrat_confidence = "LOW"

        strrat_heuristics = {
            "is_strrat_candidate": is_strrat_candidate,
            "confidence": strrat_confidence,
            "matched_indicators": strrat_matches,
            "explanation": (
                "Matches hallmark forensic indicators of the STRRAT Remote Access Trojan documented in the SecurityScorecard Case Study: "
                "Allatori obfuscation, fake ransomware (.crimson) extension simulation, credential harvesting, Task Scheduler persistence, and raw TCP C2 communications."
                if is_strrat_candidate else "No conclusive STRRAT signature pattern matched."
            )
        }

        code_obfuscation = {
            "is_obfuscated": is_obfuscated,
            "score": obf_score,
            "verdict": obf_verdict,
            "summary": obf_summary,
            "obfuscators": obfuscators,
            "single_letter_class_ratio": round(ratio, 2),
            "total_classes": total_classes,
            "obfuscated_classes_count": obfuscated_classes,
            "indicators": indicators,
            "strrat_heuristics": strrat_heuristics
        }

        return {
            "internet_activity": internet_activity,
            "file_access": file_access,
            "command_execution": command_execution,
            "code_obfuscation": code_obfuscation,
            "strrat_heuristics": strrat_heuristics
        }

    def _generate_behavioral_findings(self, behavioral: Dict[str, Any], findings: List[Finding], data: Dict[str, Any]):
        """Generates structured Findings for behavioral risk factors and STRRAT matches."""
        if not behavioral:
            return

        strrat = behavioral.get("strrat_heuristics", {})
        if strrat.get("is_strrat_candidate") and strrat.get("confidence") in ("HIGH", "MEDIUM"):
            conf = strrat["confidence"]
            matched_str = ", ".join(strrat.get("matched_indicators", []))
            findings.append(Finding(
                category="malware",
                severity="critical",
                title=f"Threat Intel Match: STRRAT Java RAT ({conf} Confidence)",
                description=(
                    f"Archive/bytecode exhibits textbook forensic indicators of the STRRAT Remote Access Trojan "
                    f"(SecurityScorecard Case Study). Key hallmarks detected: {matched_str}."
                ),
                details=strrat
            ))
            rat_name = "STRRAT Java RAT / Crimson Infostealer (SecurityScorecard Case Study)"
            if rat_name not in data.get("rat_detections", []):
                data.setdefault("rat_detections", []).append(rat_name)

        int_act = behavioral.get("internet_activity", {})
        if int_act.get("score", 0) >= 50 or any(c.get("severity") == "critical" for c in int_act.get("capabilities", [])):
            caps_str = ", ".join([c["name"] for c in int_act.get("capabilities", [])])
            findings.append(Finding(
                category="network",
                severity="high" if int_act.get("score", 0) >= 60 else "medium",
                title="Forensic Behavioral Finding: 🌐 Suspicious Internet & Server Activity",
                description=f"{int_act.get('summary', '')} Discovered capabilities: {caps_str}.",
                details=int_act
            ))

        file_acc = behavioral.get("file_access", {})
        if file_acc.get("score", 0) >= 50 or any(c.get("severity") == "critical" for c in file_acc.get("capabilities", [])):
            is_crit = any(c.get("id") in ("credential_harvesting", "ransomware_simulation") for c in file_acc.get("capabilities", []))
            caps_str = ", ".join([c["name"] for c in file_acc.get("capabilities", [])])
            findings.append(Finding(
                category="filesystem",
                severity="critical" if is_crit else "high",
                title="Forensic Behavioral Finding: 📂 Broad File Access & Credential Harvesting",
                description=f"{file_acc.get('summary', '')} Discovered capabilities: {caps_str}.",
                details=file_acc
            ))

        cmd_exec = behavioral.get("command_execution", {})
        if cmd_exec.get("score", 0) >= 50 or any(c.get("severity") == "critical" for c in cmd_exec.get("capabilities", [])):
            caps_str = ", ".join([c["name"] for c in cmd_exec.get("capabilities", [])])
            findings.append(Finding(
                category="execution",
                severity="critical",
                title="Forensic Behavioral Finding: 🛠 Host Operating System Shell Command Execution",
                description=f"{cmd_exec.get('summary', '')} Discovered capabilities: {caps_str}.",
                details=cmd_exec
            ))

        code_obf = behavioral.get("code_obfuscation", {})
        if code_obf.get("is_obfuscated") and code_obf.get("score", 0) >= 50:
            obf_str = ", ".join(code_obf.get("obfuscators", [])) if code_obf.get("obfuscators") else "High Obfuscation"
            ind_str = ", ".join([i["name"] for i in code_obf.get("indicators", [])])
            findings.append(Finding(
                category="evasion",
                severity="high",
                title=f"Forensic Behavioral Finding: 🧩 Obfuscated Code ({obf_str})",
                description=f"{code_obf.get('summary', '')} Indicators: {ind_str}.",
                details=code_obf
            ))

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

            # 4-Pillar Behavioral Analysis (SecurityScorecard Methodology)
            raw_corpus = content + " " + " ".join([a.get("code", "") for a in detected_apis])
            data["behavioral_analysis"] = self._audit_behavioral_capabilities(
                strings=lines,
                method_calls=[{"class": a.get("api", ""), "method": a.get("api", ""), "descriptor": "", "full": a.get("api", "")} for a in detected_apis],
                class_names=[data["class_name"]] if data.get("class_name") else [],
                namelist=[Path(file_path).name],
                manifest_text="",
                embedded_binaries=[],
                raw_text_corpus=raw_corpus,
                iocs=data["iocs"]
            )
            data["strrat_profile"] = data["behavioral_analysis"]["strrat_heuristics"]
            self._generate_behavioral_findings(data["behavioral_analysis"], findings, data)

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

                # Class metadata
                data["class_info"] = {
                    "major_version": parser.major_version,
                    "minor_version": parser.minor_version,
                    "java_version": parser.java_version_name,
                    "constant_pool_count": len(parser.constant_pool),
                    "methods_count": len(parser.method_calls),
                    "interfaces_count": len(parser.interfaces)
                }

                # Check Java RAT signatures across strings
                joined_all = " ".join(parser.strings) + " " + " ".join([m["full"] for m in parser.method_calls])
                for rat in JAVA_RAT_SIGNATURES:
                    if any(p.search(joined_all) for p in rat["patterns"]):
                        data["rat_detections"].append(rat["name"])
                        findings.append(Finding(
                            category="malware",
                            severity=rat["severity"],
                            title=f"Malicious Java Signature Match: {rat['name']}",
                            description=f"Class bytecode matches structural signatures associated with {rat['name']}.",
                            details={"rat_family": rat["name"]}
                        ))

                # 4-Pillar Behavioral Analysis (SecurityScorecard Methodology)
                data["behavioral_analysis"] = self._audit_behavioral_capabilities(
                    strings=parser.strings,
                    method_calls=parser.method_calls,
                    class_names=[parser.class_name] if parser.class_name else [],
                    namelist=[Path(file_path).name],
                    manifest_text="",
                    embedded_binaries=[],
                    raw_text_corpus=joined_all,
                    iocs=data["iocs"]
                )
                data["strrat_profile"] = data["behavioral_analysis"]["strrat_heuristics"]
                self._generate_behavioral_findings(data["behavioral_analysis"], findings, data)

        except Exception as e:
            logger.debug(f"Java class analysis error: {e}")

    def _inspect_jar_signature(self, zf: zipfile.ZipFile, namelist: List[str], findings: List[Finding]) -> Tuple[str, Dict[str, Any]]:
        """
        Inspects JAR digital signatures (META-INF/*.SF, META-INF/*.RSA, *.DSA, *.EC).
        Parses signer certificates, validity dates, self-signed status, and generates findings.
        """
        sig_info: Dict[str, Any] = {
            "is_signed": False,
            "signer_name": None,
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "valid_from": None,
            "valid_until": None,
            "sha256_fingerprint": None,
            "sha1_fingerprint": None,
            "signature_algorithm": None,
            "is_self_signed": False,
            "is_expired": False,
            "is_debug_key": False,
            "is_partially_signed": False,
            "unsigned_classes_count": 0,
            "unsigned_classes": [],
            "manifest_digests_count": 0,
            "signature_files": []
        }

        sig_files = [n for n in namelist if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))]
        sig_info["signature_files"] = sig_files

        if not sig_files:
            return "UNSIGNED", sig_info

        # Count digest entries and track signed file names in .SF
        signed_files = set()
        for sf_name in sig_files:
            if sf_name.upper().endswith(".SF"):
                try:
                    sf_text = zf.read(sf_name).decode("utf-8", errors="ignore")
                    digests = re.findall(r"(?:SHA-256|SHA1)-Digest:", sf_text, re.I)
                    sig_info["manifest_digests_count"] = max(sig_info["manifest_digests_count"], len(digests))
                    for name_match in re.finditer(r'^Name:\s*([^\r\n]+)', sf_text, re.M):
                        signed_files.add(name_match.group(1).strip())
                except Exception:
                    pass

        # Signed entry coverage: check for unsigned executable .class files
        class_files = [n for n in namelist if n.endswith(".class") and not n.startswith("META-INF/")]
        if signed_files and class_files:
            unsigned_classes = [c for c in class_files if c not in signed_files]
            if unsigned_classes:
                sig_info["is_partially_signed"] = True
                sig_info["unsigned_classes_count"] = len(unsigned_classes)
                sig_info["unsigned_classes"] = unsigned_classes[:15]
                findings.append(Finding(
                    category="signature",
                    severity="high",
                    title=f"Partially Signed JAR: {len(unsigned_classes)} Unsigned Classes Detected",
                    description=(
                        f"Archive is digitally signed but contains {len(unsigned_classes)} unsigned executable class file(s) "
                        f"(e.g. '{unsigned_classes[0]}'). This indicates partial signing, incomplete build verification, "
                        "or potential class injection / signature bypass tampering."
                    ),
                    details={"unsigned_classes": unsigned_classes[:25], "total_unsigned": len(unsigned_classes)}
                ))

        # Find signature block file
        sig_block = next((n for n in sig_files if n.upper().endswith((".RSA", ".DSA", ".EC"))), None)
        if not sig_block:
            sig_info["is_signed"] = True
            sig_info["signer_name"] = "Signed (Signature File Present)"
            return "SIGNED", sig_info

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timezone

            cert_bytes = zf.read(sig_block)
            cert = None
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            except Exception:
                start = cert_bytes.find(b"\x30\x82")
                while start != -1:
                    try:
                        seq_len = struct.unpack_from(">H", cert_bytes, start + 2)[0]
                        candidate = cert_bytes[start:start + seq_len + 4]
                        cert = x509.load_der_x509_certificate(candidate, default_backend())
                        if cert:
                            break
                    except Exception:
                        pass
                    start = cert_bytes.find(b"\x30\x82", start + 1)

            if cert:
                sig_info["is_signed"] = True
                subject_str = cert.subject.rfc4514_string()
                issuer_str = cert.issuer.rfc4514_string()

                cn_match = re.search(r'CN=([^,]+)', subject_str)
                signer_cn = cn_match.group(1) if cn_match else subject_str

                der_bytes = cert.public_bytes(x509.Encoding.DER)
                sha256_fp = hashlib.sha256(der_bytes).hexdigest()
                sha1_fp = hashlib.sha1(der_bytes).hexdigest()

                valid_from = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
                valid_until = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)

                sig_info["signer_name"] = signer_cn
                sig_info["subject"] = subject_str
                sig_info["issuer"] = issuer_str
                sig_info["serial_number"] = hex(cert.serial_number)
                sig_info["valid_from"] = valid_from
                sig_info["valid_until"] = valid_until
                sig_info["sha256_fingerprint"] = sha256_fp
                sig_info["sha1_fingerprint"] = sha1_fp
                sig_info["signature_algorithm"] = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)

                if subject_str == issuer_str:
                    sig_info["is_self_signed"] = True

                now = datetime.now(timezone.utc)
                cert_end = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
                if now > cert_end:
                    sig_info["is_expired"] = True

                if any(term in subject_str.lower() for term in ["android debug", "test key", "example", "self-signed"]):
                    sig_info["is_debug_key"] = True

                status_str = "SIGNED"
                if sig_info["is_expired"]:
                    status_str = "SIGNED (EXPIRED)"
                    findings.append(Finding(
                        category="signature",
                        severity="high",
                        title=f"Expired JAR Code Signing Certificate ('{signer_cn}')",
                        description=f"JAR digital certificate expired on {valid_until[:10]}. Software signed with expired certificates cannot guarantee publisher verification.",
                        details=sig_info
                    ))
                elif sig_info["is_debug_key"]:
                    status_str = "SIGNED (DEBUG KEY)"
                    findings.append(Finding(
                        category="signature",
                        severity="high",
                        title=f"Test/Debug Code Signing Key Detected ('{signer_cn}')",
                        description=f"Archive was signed using a public or debug keystore ('{signer_cn}'). Production software must never be distributed with debug keys.",
                        details=sig_info
                    ))
                elif sig_info["is_self_signed"]:
                    status_str = "SIGNED (SELF-SIGNED)"
                    findings.append(Finding(
                        category="signature",
                        severity="medium",
                        title=f"Self-Signed JAR Digital Certificate ('{signer_cn}')",
                        description=f"JAR is signed by a self-issued certificate rather than a trusted public Certificate Authority (CA).",
                        details=sig_info
                    ))
                else:
                    findings.append(Finding(
                        category="signature",
                        severity="info",
                        title=f"Cryptographically Signed Java Archive ('{signer_cn}')",
                        description=f"Archive contains valid X.509 code signature issued to '{signer_cn}' (Valid until {valid_until[:10]}).",
                        details=sig_info
                    ))

                return status_str, sig_info

        except Exception as e:
            logger.debug(f"JAR signature parsing note: {e}")

        sig_info["is_signed"] = True
        sig_info["signer_name"] = "Signed (Embedded PKCS#7 Block)"
        return "SIGNED", sig_info

    def _categorize_strings(self, all_strings: List[str]) -> Tuple[List[str], Dict[str, List[str]], int]:
        """
        Categorizes extracted strings into Network, File Paths, Registry, Commands, and All.
        Matches PE/ELF binary string categorization format.
        """
        seen = set()
        cleaned = []
        for s in all_strings:
            if isinstance(s, str):
                st = s.strip()
                if 3 <= len(st) <= 500 and st not in seen:
                    printable_ratio = sum(1 for c in st if c.isprintable()) / len(st)
                    if printable_ratio >= 0.75:
                        seen.add(st)
                        cleaned.append(st)

        network = []
        file_paths = []
        registry = []
        commands = []

        net_pat = re.compile(r'https?://|(?:(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)|(?:[a-zA-Z0-9_\-\.]+\.(?:com|org|net|io|ru|xyz|top|cc|biz|info|cn)(?::\d+)?)|socks[45]?://|irc://', re.I)
        fp_pat = re.compile(r'(?:[a-zA-Z]:\\|(?:/(?:etc|tmp|var|usr|bin|root|home|dev|proc)/)|%[A-Za-z_]+%|user\.home|appdata|\.crimson|lock\.file|\.jar|\.exe|\.dll|\.sh|\.bat)', re.I)
        reg_pat = re.compile(r'(?:CurrentVersion\\Run|HKEY_|HKLM|HKCU|Software\\Microsoft\\Windows)', re.I)
        cmd_pat = re.compile(r'(?:cmd\.exe|powershell(?:\.exe)?|schtasks(?:\.exe)?|reg(?:\.exe)?|certutil(?:\.exe)?|wscript|cscript|taskkill|vssadmin|attrib|/bin/sh|/bin/bash|curl|wget)', re.I)

        for s in cleaned:
            if net_pat.search(s):
                network.append(s)
            if fp_pat.search(s):
                file_paths.append(s)
            if reg_pat.search(s):
                registry.append(s)
            if cmd_pat.search(s):
                commands.append(s)

        all_sample = sorted(cleaned, key=lambda x: (
            0 if any(c in x.lower() for c in ["http", "powershell", "cmd", "run", "crimson", "socket"]) else 1,
            -len(x)
        ))[:150]

        categorized = {
            "network": sorted(list(set(network)))[:100],
            "file_paths": sorted(list(set(file_paths)))[:100],
            "registry": sorted(list(set(registry)))[:100],
            "commands": sorted(list(set(commands)))[:100]
        }

        return all_sample, categorized, len(cleaned)

    def _extract_base64_blocks(self, corpus: str, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Extracts, decodes, and analyzes Base64 blocks from JAR strings/resources.
        Matches Script & Python triage functionality.
        """
        b64_blocks = []
        try:
            from app.analyzers.deobfuscator import Deobfuscator
            raw_b64_list = Deobfuscator.scan_for_base64_blocks(corpus)
            for b64_item in raw_b64_list[:15]:
                enc_preview = b64_item.get("encoded", "")
                enc_full = b64_item.get("encoded_full", enc_preview)
                dec = b64_item.get("decoded", "")
                encoding = b64_item.get("encoding", "UTF-8")
                is_binary = b64_item.get("is_binary", False)

                is_critical = is_binary or any(kw in dec.lower() for kw in [
                    "invoke-expression", "iex", "downloadstring", "downloadfile", "webclient",
                    "virtualalloc", "writeprocessmemory", "createremotethread", "amsiutils",
                    "cmd.exe", "powershell", "wscript.shell", "/bin/sh", "curl", "wget", "nc ",
                    "socket", "runtime.exec", "processbuilder"
                ])

                block_entry = {
                    "encoded": enc_preview,
                    "encoded_full": enc_full,
                    "decoded_preview": dec[:140].strip(),
                    "encoding": encoding,
                    "length": len(enc_full),
                    "threat": "HIGH_CONFIDENCE_PAYLOAD" if is_critical else "SUSPICIOUS_ENCODED",
                    "extracted_urls": b64_item.get("extracted_urls", []),
                    "extracted_ips": b64_item.get("extracted_ips", []),
                    "iocs": b64_item.get("extracted_urls", []) + b64_item.get("extracted_ips", []),
                    "is_critical": is_critical
                }
                b64_blocks.append(block_entry)

                if is_critical or len(b64_item.get("extracted_urls", [])) > 0:
                    findings.append(Finding(
                        category="deobfuscation",
                        severity="critical" if is_critical else "high",
                        title=f"Decoded Base64 Payload in JAR ({encoding})",
                        description=(
                            f"Extracted Base64 string '{enc_preview}'. "
                            f"Decoded content reveals: {dec[:180]}"
                        ),
                        details=block_entry
                    ))
        except Exception as e:
            logger.debug(f"JAR Base64 scan note: {e}")
        return b64_blocks

    def _extract_lolbins_and_commands(self, corpus: str, strings: List[str]) -> Tuple[List[Dict[str, Any]], bool, List[str]]:
        """
        Extracts Living-off-the-Land (LOLBins) and OS host commands.
        Matches Script triage functionality.
        """
        lolbin_catalog = [
            ("certutil", "Defense Evasion / Download Cradle", "Command-line utility used to download and decode malicious payloads."),
            ("powershell", "Execution / Download Cradle", "Windows automation engine abused to execute memory-only scripts."),
            ("bitsadmin", "Defense Evasion / Persistence", "Background Intelligent Transfer Service abused to download malicious payloads."),
            ("wscript", "Execution", "Windows Script Host abused to execute VBScript or JScript payloads."),
            ("cscript", "Execution", "Console-based script host abused for script execution."),
            ("mshta", "Execution / Defense Evasion", "Microsoft HTML Application host abused to execute remote scripts."),
            ("rundll32", "Defense Evasion / Execution", "Executes 32-bit DLLs directly from command line."),
            ("regsvr32", "Defense Evasion", "Registers and executes in-memory scriptlet DLLs (Squiblydoo)."),
            ("schtasks", "Persistence / Execution", "Schedules tasks for persistence and elevated execution."),
            ("reg", "Persistence / Defense Evasion", "Modifies Windows Registry Run keys or security settings."),
            ("taskkill", "Defense Evasion", "Terminates security and monitoring software processes."),
            ("vssadmin", "Impact / Ransomware", "Deletes Volume Shadow Copies to prevent system recovery."),
            ("attrib", "Defense Evasion", "Hides malicious files with system and hidden attributes."),
            ("sc", "Persistence", "Creates and manages malicious Windows services.")
        ]
        matched_lolbins = []
        detected_commands = []

        for bin_name, category, description in lolbin_catalog:
            if re.search(r'(?i)\b' + re.escape(bin_name) + r'(?:\.exe)?\b', corpus):
                matched_sample = next((s for s in strings if isinstance(s, str) and bin_name in s.lower()), bin_name)
                matched_lolbins.append({
                    "name": bin_name,
                    "category": category,
                    "description": description,
                    "matched_in": "Bytecode String Constants",
                    "matched_text": matched_sample[:140]
                })

        cmd_patterns = [
            r'(?i)cmd(?:\.exe)?\s+/c\s+["\']?([^"\'\n\r]+)',
            r'(?i)powershell(?:\.exe)?\s+-[a-zA-Z]+\s+([^"\'\n\r]+)',
            r'(?i)schtasks(?:\.exe)?\s+(?:/create|/run|/delete)[^"\'\n\r]*',
            r'(?i)reg(?:\.exe)?\s+(?:add|delete)[^"\'\n\r]*',
            r'(?i)(?:/bin/sh|/bin/bash)\s+-c\s+["\']?([^"\'\n\r]+)'
        ]
        for pat in cmd_patterns:
            for m in re.finditer(pat, corpus):
                detected_commands.append(m.group(0)[:120])

        for s in strings:
            if isinstance(s, str) and len(s) > 4:
                s_low = s.lower()
                if any(k in s_low for k in ["cmd.exe /c", "powershell -enc", "schtasks /create", "reg add", "taskkill /f", "vssadmin delete"]):
                    detected_commands.append(s[:120])

        has_lolbins = len(matched_lolbins) > 0
        return matched_lolbins, has_lolbins, list(set(detected_commands))[:30]

    def _inspect_embedded_resources(self, infos: List[zipfile.ZipInfo]) -> List[Dict[str, Any]]:
        """
        Categorizes embedded resources inside the JAR archive (configs, scripts, native libraries).
        Matches Binary resources and APK asset functionality.
        """
        resources = []
        for info in infos:
            if info.filename.endswith(".class") or info.filename == "META-INF/MANIFEST.MF":
                continue
            ext = Path(info.filename).suffix.lower()
            size = info.file_size
            size_fmt = f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"
            is_binary = ext in [".dll", ".so", ".dylib", ".exe", ".bin", ".dat", ".png", ".jpg", ".ico", ".rsa", ".dsa"]
            is_dangerous = ext in [".dll", ".so", ".dylib", ".exe", ".sh", ".bat", ".cmd", ".ps1", ".vbs"]
            threat_reason = None
            if ext in [".dll", ".so", ".dylib", ".exe"]:
                threat_reason = "Native binary executable or shared library bundled inside Java Archive"
            elif ext in [".sh", ".bat", ".cmd", ".ps1", ".vbs"]:
                threat_reason = "Dropper shell/batch script packaged inside Java Archive"

            is_executable = ext in [".dll", ".so", ".dylib", ".exe"]
            is_script = ext in [".sh", ".bat", ".cmd", ".ps1", ".vbs", ".py", ".js"]
            is_archive = ext in [".zip", ".tar", ".gz", ".jar", ".7z", ".rar"]
            is_config = ext in [".json", ".xml", ".yml", ".yaml", ".properties", ".ini", ".conf"]
            threat_level = "DANGEROUS" if is_executable else ("SUSPICIOUS" if is_script else "INFO")
            res_type = "Native Executable" if is_executable else ("Script" if is_script else ("Archive" if is_archive else ("Configuration" if is_config else "Resource")))

            resources.append({
                "name": info.filename,
                "size": size,
                "size_formatted": size_fmt,
                "type": res_type,
                "extension": ext or "none",
                "is_executable": is_executable,
                "is_script": is_script,
                "is_archive": is_archive,
                "is_config": is_config,
                "threat_level": threat_level,
                "is_binary": is_binary,
                "is_dangerous": is_dangerous,
                "threat_reason": threat_reason
            })
        return resources

    def _audit_archive_security(
        self,
        file_path: Path,
        zf: zipfile.ZipFile,
        infos: List[zipfile.ZipInfo],
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Audits archive structural integrity and anti-parser security:
        - Path traversal / Zip Slip vulnerability (../ or absolute paths)
        - Decompression ratio / Zip Bomb resource exhaustion
        - Duplicate central-directory / local-header entries
        - Extension & magic byte mismatches (e.g. .png hiding .class or PE)
        - Polyglot & trailing data inspection (appended payloads past EOCD)
        - Nested archives (embedded JAR, WAR, EAR, ZIP)
        """
        zip_slip_paths = []
        for info in infos:
            fn = info.filename
            if "../" in fn or "..\\" in fn or fn.startswith(("/", "\\")) or re.match(r'^[a-zA-Z]:[/\\]', fn):
                zip_slip_paths.append(fn)

        if zip_slip_paths:
            findings.append(Finding(
                category="archive_security",
                severity="critical",
                title=f"Zip Slip Vulnerability Detected ({len(zip_slip_paths)} Traversal Paths)",
                description=(
                    f"Archive contains {len(zip_slip_paths)} file path(s) using directory traversal characters ('../') "
                    f"or absolute roots (e.g. '{zip_slip_paths[0]}'). Unpacking this archive without sanitization will "
                    "cause files to be written outside the target directory, enabling arbitrary file overwrite / code execution."
                ),
                details={"paths": zip_slip_paths[:20]}
            ))

        total_uncompressed = sum(i.file_size for i in infos)
        total_compressed = sum(i.compress_size for i in infos)
        disk_size = file_path.stat().st_size if file_path.exists() else total_compressed

        ratio_compressed = total_uncompressed / max(1, total_compressed)
        ratio_disk = total_uncompressed / max(1, disk_size)
        comp_ratio = round(max(ratio_compressed, ratio_disk), 1)

        is_bomb = comp_ratio >= 100 or (total_uncompressed >= 200_000_000 and comp_ratio >= 50)
        if is_bomb:
            sev = "critical" if comp_ratio >= 100 or total_uncompressed >= 500_000_000 else "high"
            findings.append(Finding(
                category="archive_security",
                severity=sev,
                title=f"Potential Zip Bomb / Resource Exhaustion ({comp_ratio}:1 Expansion)",
                description=(
                    f"Archive exhibits an abnormal compression ratio of {comp_ratio}:1 "
                    f"(Compressed: {total_compressed / (1024*1024):.2f} MB, Uncompressed: {total_uncompressed / (1024*1024):.2f} MB). "
                    "Attempting decompression may cause denial-of-service via memory or disk exhaustion."
                ),
                details={
                    "compression_ratio": comp_ratio,
                    "uncompressed_bytes": total_uncompressed,
                    "compressed_bytes": total_compressed,
                    "disk_bytes": disk_size
                }
            ))

        # Duplicate entries
        all_names = [i.filename for i in infos]
        counts = Counter(all_names)
        duplicates = [name for name, count in counts.items() if count > 1]
        if duplicates:
            findings.append(Finding(
                category="archive_security",
                severity="medium",
                title=f"Archive Integrity: Duplicate Entries Detected ({len(duplicates)} Paths)",
                description=(
                    f"Archive contains {len(duplicates)} duplicate path entries (e.g. '{duplicates[0]}'). "
                    "Conflicting entries can cause security tools, Java classloaders, and archive extractors "
                    "to process different versions of classes or resources, bypassing security filters."
                ),
                details={"duplicates": duplicates[:20]}
            ))

        # Extension and Content Mismatch
        mismatches = []
        disguised_types = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".txt", ".csv",
            ".pdf", ".css", ".json", ".xml", ".properties", ".svg", ".log"
        }
        for info in infos[:250]:
            ext = Path(info.filename).suffix.lower()
            if ext in disguised_types and info.file_size > 16:
                try:
                    head = zf.read(info.filename)[:32]
                    actual = None
                    if head.startswith(b"\xca\xfe\xba\xbe"):
                        actual = "Java Compiled Class (Bytecode)"
                    elif head.startswith(b"MZ"):
                        actual = "Windows PE Executable / DLL"
                    elif head.startswith(b"\x7fELF"):
                        actual = "Linux ELF Executable / Shared Object"
                    elif head.startswith(b"PK\x03\x04"):
                        actual = "Embedded ZIP / JAR Archive"
                    elif head.startswith(b"#!") or any(kw in head.lower() for kw in [b"powershell", b"wscript", b"cmd.exe"]):
                        actual = "Shell / Script Executable"

                    if actual:
                        mismatches.append({
                            "filename": info.filename,
                            "declared_extension": ext,
                            "actual_type": actual,
                            "file_size": info.file_size,
                            "threat_level": "critical" if "Executable" in actual or "Bytecode" in actual else "high"
                        })
                except Exception:
                    pass

        if mismatches:
            for m in mismatches[:5]:
                findings.append(Finding(
                    category="archive_security",
                    severity=m["threat_level"],
                    title=f"Concealed Executable / Disguised Content ({m['filename']})",
                    description=(
                        f"Entry '{m['filename']}' possesses innocuous extension '{m['declared_extension']}' "
                        f"but actually contains {m['actual_type']}. Threat actors use this technique to bypass firewalls and inspection."
                    ),
                    details=m
                ))

        # Polyglot and Trailing Data Inspection
        has_trailing = False
        trailing_bytes = 0
        has_polyglot = False
        leading_magic = "ZIP"

        try:
            with open(file_path, "rb") as f:
                head16 = f.read(16)
                if not head16.startswith(b"PK\x03\x04") and not head16.startswith(b"PK\x05\x06"):
                    has_polyglot = True
                    if head16.startswith(b"GIF89a") or head16.startswith(b"GIF87a"):
                        leading_magic = "GIF (GIFAR Polyglot)"
                    elif head16.startswith(b"\xff\xd8\xff"):
                        leading_magic = "JPEG Image Polyglot"
                    elif head16.startswith(b"%PDF"):
                        leading_magic = "PDF Document Polyglot"
                    elif head16.startswith(b"MZ"):
                        leading_magic = "Windows PE Polyglot"
                    elif head16.startswith(b"\x7fELF"):
                        leading_magic = "Linux ELF Polyglot"
                    else:
                        leading_magic = f"Custom Header ({head16[:8].hex()})"

                # Check for trailing data after EOCD
                f.seek(0, 2)
                fsize = f.tell()
                search_len = min(fsize, 65557)
                f.seek(fsize - search_len)
                tail = f.read(search_len)
                eocd_idx = tail.rfind(b"PK\x05\x06")
                if eocd_idx != -1:
                    eocd_pos = (fsize - search_len) + eocd_idx
                    if len(tail) >= eocd_idx + 22:
                        comment_len = struct.unpack_from("<H", tail, eocd_idx + 20)[0]
                        expected_end = eocd_pos + 22 + comment_len
                        if fsize > expected_end + 32:
                            has_trailing = True
                            trailing_bytes = fsize - expected_end
        except Exception as e:
            logger.debug(f"Polyglot inspection note: {e}")

        if has_polyglot or has_trailing:
            details_obj = {
                "has_polyglot": has_polyglot,
                "leading_magic": leading_magic,
                "has_trailing_data": has_trailing,
                "trailing_bytes": trailing_bytes
            }
            title = "Polyglot Archive Structure" if has_polyglot else f"Appended Trailing Data ({trailing_bytes} bytes)"
            findings.append(Finding(
                category="archive_security",
                severity="high" if has_polyglot else "medium",
                title=title,
                description=(
                    f"Archive exhibits anomalous structure: "
                    + (f"starts with {leading_magic} instead of standard ZIP header. " if has_polyglot else "")
                    + (f"Contains {trailing_bytes} trailing bytes after the End of Central Directory record." if has_trailing else "")
                ),
                details=details_obj
            ))

        # Nested archives
        nested_archives = []
        archive_exts = {".jar", ".war", ".ear", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z"}
        for info in infos:
            ext = Path(info.filename).suffix.lower()
            if ext in archive_exts:
                nested_archives.append({
                    "filename": info.filename,
                    "size": info.file_size,
                    "type": ext.lstrip(".").upper()
                })

        issues_count = (
            len(zip_slip_paths) +
            (1 if is_bomb else 0) +
            len(duplicates) +
            len(mismatches) +
            (1 if has_polyglot else 0) +
            (1 if has_trailing else 0)
        )

        verdict = "SECURE"
        if zip_slip_paths or is_bomb or mismatches:
            verdict = "VULNERABLE"
        elif duplicates or has_polyglot or has_trailing or len(nested_archives) > 5:
            verdict = "SUSPICIOUS"

        return {
            "zip_slip": {
                "detected": len(zip_slip_paths) > 0,
                "paths": zip_slip_paths[:20],
                "count": len(zip_slip_paths)
            },
            "zip_bomb": {
                "detected": is_bomb,
                "compression_ratio": comp_ratio,
                "uncompressed_size": total_uncompressed,
                "compressed_size": total_compressed,
                "disk_size": disk_size,
                "is_dangerous": is_bomb
            },
            "duplicate_entries": {
                "detected": len(duplicates) > 0,
                "entries": duplicates[:20],
                "count": len(duplicates)
            },
            "extension_mismatches": mismatches,
            "polyglot_and_trailing": {
                "has_trailing_data": has_trailing,
                "trailing_bytes_count": trailing_bytes,
                "has_leading_polyglot": has_polyglot,
                "leading_magic": leading_magic
            },
            "nested_archives": nested_archives,
            "issues_count": issues_count,
            "verdict": verdict
        }

    def _parse_version(self, v: str) -> Tuple[int, ...]:
        clean = re.sub(r'[^0-9.]', '', v)
        parts = clean.split(".")
        res = []
        for p in parts:
            try:
                res.append(int(p))
            except ValueError:
                res.append(0)
        return tuple(res) if res else (0,)

    def _is_version_less_than(self, v: str, target: str) -> bool:
        try:
            return self._parse_version(v) < self._parse_version(target)
        except Exception:
            return False

    def _audit_dependencies_and_sbom(
        self,
        zf: zipfile.ZipFile,
        infos: List[zipfile.ZipInfo],
        namelist: List[str],
        manifest_dict: Dict[str, str],
        packages: Set[str],
        findings: List[Finding]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """
        Extracts dependencies from Maven pom.properties / pom.xml, Manifest headers,
        detects shaded libraries and Multi-Release JARs, correlates known CVEs
        (Log4Shell, Spring4Shell, Commons-Collections, Fastjson, SnakeYAML, XStream),
        and generates a CycloneDX v1.4 JSON SBOM.
        """
        dependencies: List[Dict[str, Any]] = []
        seen_deps = set()

        # 1. Maven pom.properties inspection
        pom_prop_files = [n for n in namelist if "pom.properties" in n.lower() and n.startswith("META-INF/maven/")]
        for pfile in pom_prop_files:
            try:
                ptext = zf.read(pfile).decode("utf-8", errors="ignore")
                dep_info: Dict[str, str] = {}
                for line in ptext.splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        dep_info[k.strip()] = v.strip()
                gid = dep_info.get("groupId", "")
                aid = dep_info.get("artifactId", "")
                ver = dep_info.get("version", "")
                if aid and (gid, aid, ver) not in seen_deps:
                    seen_deps.add((gid, aid, ver))
                    dependencies.append({
                        "group_id": gid or "unknown",
                        "artifact_id": aid,
                        "version": ver or "unknown",
                        "source": pfile,
                        "type": "maven"
                    })
            except Exception:
                pass

        # 2. Maven pom.xml inspection if pom.properties missing
        if not dependencies:
            pom_xml_files = [n for n in namelist if n.endswith("pom.xml") and n.startswith("META-INF/maven/")]
            for px in pom_xml_files:
                try:
                    xml_text = zf.read(px).decode("utf-8", errors="ignore")
                    gid_m = re.search(r'<groupId>([^<]+)</groupId>', xml_text)
                    aid_m = re.search(r'<artifactId>([^<]+)</artifactId>', xml_text)
                    ver_m = re.search(r'<version>([^<]+)</version>', xml_text)
                    if aid_m:
                        gid = gid_m.group(1).strip() if gid_m else "unknown"
                        aid = aid_m.group(1).strip()
                        ver = ver_m.group(1).strip() if ver_m else "unknown"
                        if (gid, aid, ver) not in seen_deps:
                            seen_deps.add((gid, aid, ver))
                            dependencies.append({
                                "group_id": gid,
                                "artifact_id": aid,
                                "version": ver,
                                "source": px,
                                "type": "maven_xml"
                            })
                except Exception:
                    pass

        # 3. Fallback: Manifest-based primary dependency
        title = manifest_dict.get("implementation-title") or manifest_dict.get("bundle-symbolicname") or manifest_dict.get("specification-title")
        version = manifest_dict.get("implementation-version") or manifest_dict.get("bundle-version") or manifest_dict.get("specification-version")
        if title and not dependencies:
            dependencies.append({
                "group_id": "manifest",
                "artifact_id": title,
                "version": version or "unknown",
                "source": "META-INF/MANIFEST.MF",
                "type": "manifest"
            })

        # 4. Multi-Release JAR Check
        multi_release_versions = []
        mr_pattern = re.compile(r'^META-INF/versions/(\d+)/')
        for n in namelist:
            m = mr_pattern.match(n)
            if m:
                multi_release_versions.append(int(m.group(1)))
        multi_release_versions = sorted(list(set(multi_release_versions)))

        # 5. Shaded Library Detection
        shaded_signatures = [
            ("org.apache.commons", "Apache Commons", "utility"),
            ("org.apache.logging.log4j", "Apache Log4j", "logging"),
            ("org.apache.log4j", "Apache Log4j 1.x", "logging"),
            ("com.google.gson", "Google Gson", "json"),
            ("com.google.common", "Google Guava", "utility"),
            ("com.fasterxml.jackson", "Jackson Databind", "json"),
            ("org.slf4j", "SLF4J Logger", "logging"),
            ("ch.qos.logback", "Logback", "logging"),
            ("io.netty", "Netty Network Framework", "network"),
            ("org.springframework", "Spring Framework", "framework"),
            ("org.yaml.snakeyaml", "SnakeYAML", "yaml"),
            ("com.thoughtworks.xstream", "XStream", "xml"),
            ("com.alibaba.fastjson", "Fastjson", "json"),
            ("org.bouncycastle", "Bouncy Castle Crypto", "crypto"),
            ("org.sqlite", "SQLite JDBC Driver", "database"),
            ("com.mysql", "MySQL Connector", "database"),
            ("org.postgresql", "PostgreSQL JDBC Driver", "database"),
            ("org.apache.http", "Apache HttpComponents", "network")
        ]
        shaded_libraries = []
        for prefix, lib_name, cat in shaded_signatures:
            if any(p.startswith(prefix) for p in packages):
                matching_count = sum(1 for p in packages if p.startswith(prefix))
                shaded_libraries.append({
                    "name": lib_name,
                    "package_prefix": prefix,
                    "category": cat,
                    "packages_count": matching_count
                })

        # 6. CVE Vulnerability Correlation
        cve_advisories = []
        cve_rules = [
            {
                "artifact": "log4j-core",
                "cve": "CVE-2021-44228",
                "name": "Log4Shell JNDI Remote Code Execution",
                "severity": "critical",
                "cwe": "CWE-502 / CWE-917",
                "cvss": 10.0,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "2.17.1"),
                "description": "Log4j JNDI lookup vulnerability allows unauthenticated remote attackers to execute arbitrary code via malicious LDAP/RMI queries."
            },
            {
                "artifact": "spring-beans",
                "cve": "CVE-2022-22965",
                "name": "Spring4Shell Remote Code Execution",
                "severity": "critical",
                "cwe": "CWE-94",
                "cvss": 9.8,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "5.3.18") or (v.startswith("5.2.") and self._is_version_less_than(v, "5.2.20")),
                "description": "Spring Framework DataBinder classloader access allows unauthenticated remote attackers to execute arbitrary code on Tomcat."
            },
            {
                "artifact": "commons-collections",
                "cve": "CVE-2015-7501",
                "name": "Commons Collections InvokerTransformer Deserialization RCE",
                "severity": "critical",
                "cwe": "CWE-502",
                "cvss": 9.8,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "3.2.2") or v.startswith("4.0"),
                "description": "InvokerTransformer executes arbitrary code upon deserialization of untrusted ObjectInputStream data."
            },
            {
                "artifact": "fastjson",
                "cve": "CVE-2022-25845",
                "name": "Fastjson AutoType Bypass Deserialization RCE",
                "severity": "critical",
                "cwe": "CWE-502",
                "cvss": 9.8,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "1.2.83"),
                "description": "AutoType restriction bypass in Alibaba Fastjson allows remote code execution when parsing malicious JSON."
            },
            {
                "artifact": "snakeyaml",
                "cve": "CVE-2022-1471",
                "name": "SnakeYAML Constructor Deserialization RCE",
                "severity": "high",
                "cwe": "CWE-502",
                "cvss": 8.5,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "1.32"),
                "description": "SnakeYAML Constructor class allows remote code execution via unsafe class instantiation during YAML unmarshaling."
            },
            {
                "artifact": "xstream",
                "cve": "CVE-2021-39144",
                "name": "XStream Deserialization Remote Code Execution",
                "severity": "critical",
                "cwe": "CWE-502",
                "cvss": 9.8,
                "is_vulnerable": lambda v: self._is_version_less_than(v, "1.4.19"),
                "description": "XStream deserialization gadget execution allows arbitrary command execution via dynamic proxy handlers."
            }
        ]

        for dep in dependencies:
            aid = dep.get("artifact_id", "").lower()
            ver = dep.get("version", "")
            if not ver or ver == "unknown":
                continue
            for rule in cve_rules:
                if rule["artifact"] in aid:
                    try:
                        if rule["is_vulnerable"](ver):
                            advisory = {
                                "artifact": dep["artifact_id"],
                                "version": ver,
                                "cve": rule["cve"],
                                "name": rule["name"],
                                "severity": rule["severity"],
                                "cvss": rule["cvss"],
                                "cwe": rule["cwe"],
                                "description": rule["description"]
                            }
                            cve_advisories.append(advisory)
                            findings.append(Finding(
                                category="vulnerability",
                                severity=rule["severity"],
                                title=f"Vulnerable Dependency: {rule['cve']} ({dep['artifact_id']} {ver})",
                                description=f"{rule['name']}: {rule['description']}",
                                details=advisory
                            ))
                    except Exception as e:
                        logger.debug(f"CVE check note: {e}")

        # 7. CycloneDX v1.4 SBOM Generation
        main_name = dependencies[0]["artifact_id"] if dependencies else (title or "java-application")
        main_ver = dependencies[0]["version"] if dependencies else (version or "1.0.0")

        sbom_components = []
        for d in dependencies:
            gid = d.get("group_id", "")
            aid = d.get("artifact_id", "")
            v = d.get("version", "1.0.0")
            purl = f"pkg:maven/{gid}/{aid}@{v}" if gid and gid != "unknown" and gid != "manifest" else f"pkg:generic/{aid}@{v}"
            sbom_components.append({
                "type": "library",
                "group": gid if gid not in ["unknown", "manifest"] else "",
                "name": aid,
                "version": v,
                "purl": purl,
                "cpe": f"cpe:2.3:a:{gid or 'library'}:{aid}:{v}:*:*:*:*:*:*:*"
            })

        for s in shaded_libraries:
            sbom_components.append({
                "type": "library",
                "name": s["name"],
                "description": f"Shaded package {s['package_prefix']} ({s['packages_count']} packages)",
                "scope": "embedded"
            })

        cyclonedx_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "FileSanitizer",
                        "name": "JavaAnalyzer",
                        "version": "2.0.0"
                    }
                ],
                "component": {
                    "name": main_name,
                    "version": main_ver,
                    "type": "application"
                }
            },
            "components": sbom_components,
            "multi_release": {
                "is_multi_release": len(multi_release_versions) > 0,
                "versions": multi_release_versions
            }
        }

        return dependencies, shaded_libraries, cve_advisories, cyclonedx_sbom

    def _scan_secrets_and_ctf(
        self,
        corpus: str,
        strings: List[str],
        zf: zipfile.ZipFile,
        infos: List[zipfile.ZipInfo],
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Scans strings, decompiled bytecode, and resources for:
        - CTF flags (flag{...}, ctf{...}, picoCTF{...}, HTB{...}, etc.)
        - Hardcoded API credentials (AWS, GitHub, Slack, Private Keys, JDBC passwords, JWT)
        """
        ctf_flags = []
        secrets = []
        seen_flags = set()
        seen_secrets = set()

        flag_patterns = [
            re.compile(r'\b(flag\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I),
            re.compile(r'\b(ctf\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I),
            re.compile(r'\b(picoCTF\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I),
            re.compile(r'\b(HTB\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I),
            re.compile(r'\b(THM\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I),
            re.compile(r'\b(secflag\{[A-Za-z0-9_\-\.\$@!#%^&*+=]{3,100}\})', re.I)
        ]

        secret_patterns = [
            (
                "AWS Access Key ID",
                re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
                "critical",
                "Amazon Web Services IAM User Access Key ID."
            ),
            (
                "GitHub Personal Access Token",
                re.compile(r'\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b'),
                "critical",
                "GitHub Personal Access Token with repository or organization privileges."
            ),
            (
                "Slack OAuth / Bot Token",
                re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'),
                "high",
                "Slack API token granting access to channels and bot endpoints."
            ),
            (
                "Private Encryption Key Block",
                re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)'),
                "critical",
                "Embedded private cryptographic key header."
            ),
            (
                "Database JDBC Password",
                re.compile(r'(?:jdbc:[a-z]+://[^\r\n;]+.*?(?:password|pwd)=([^\s&;\'"]+))', re.I),
                "high",
                "Hardcoded database connection string containing plaintext credentials."
            ),
            (
                "JSON Web Token (JWT)",
                re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
                "medium",
                "Hardcoded JSON Web Token."
            )
        ]

        # Scan text corpus
        for pat in flag_patterns:
            for match in pat.finditer(corpus):
                flag = match.group(1)
                if flag not in seen_flags:
                    seen_flags.add(flag)
                    ctf_flags.append({
                        "flag": flag,
                        "format": flag.split("{")[0] + "{...}",
                        "length": len(flag)
                    })

        for name, pat, sev, desc in secret_patterns:
            for match in pat.finditer(corpus):
                val = match.group(1)
                if val not in seen_secrets:
                    seen_secrets.add(val)
                    if len(val) > 8:
                        masked = val[:4] + "*" * (len(val) - 8) + val[-4:]
                    else:
                        masked = val[:2] + "****"
                    secrets.append({
                        "type": name,
                        "masked": masked,
                        "severity": sev,
                        "description": desc,
                        "length": len(val)
                    })

        # Scan resources for hidden flag or credential files
        for info in infos[:150]:
            name_lower = info.filename.lower()
            if any(k in name_lower for k in ["flag", "secret", "creds", "password", "key.txt"]):
                try:
                    rdata = zf.read(info.filename).decode("utf-8", errors="ignore")
                    for pat in flag_patterns:
                        for match in pat.finditer(rdata):
                            flag = match.group(1)
                            if flag not in seen_flags:
                                seen_flags.add(flag)
                                ctf_flags.append({
                                    "flag": flag,
                                    "format": flag.split("{")[0] + "{...}",
                                    "length": len(flag),
                                    "source": info.filename
                                })
                except Exception:
                    pass

        # Generate findings for CTF Flags
        for f_entry in ctf_flags[:5]:
            findings.append(Finding(
                category="ctf",
                severity="high",
                title=f"CTF Flag Captured: {f_entry['flag'][:25]}...",
                description=f"Identified capture-the-flag marker '{f_entry['flag']}'.",
                details=f_entry
            ))

        # Generate findings for Secrets
        for s_entry in secrets[:5]:
            findings.append(Finding(
                category="credential",
                severity=s_entry["severity"],
                title=f"Hardcoded Credential: {s_entry['type']}",
                description=f"{s_entry['description']} Masked value: {s_entry['masked']}.",
                details=s_entry
            ))

        return {
            "detected": len(ctf_flags) > 0 or len(secrets) > 0,
            "ctf_flags": ctf_flags,
            "flags_count": len(ctf_flags),
            "secrets": secrets,
            "secrets_count": len(secrets)
        }

    def _analyze_java_archive(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]):
        data["java_type"] = "jar"
        data["java_subtype"] = "jar"
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infos = zf.infolist()
                namelist = [i.filename for i in infos]

                data["classes_count"] = sum(1 for n in namelist if n.endswith(".class"))
                data["classes_list"] = [n for n in namelist if n.endswith(".class")][:100]
                data["embedded_binaries"] = [
                    n for n in namelist
                    if Path(n).suffix.lower() in [".dll", ".so", ".dylib", ".exe", ".sh", ".bat", ".bin", ".vbs", ".ps1"]
                ]

                packages = set()
                for n in namelist:
                    if n.endswith(".class") and "/" in n:
                        packages.add("/".join(n.split("/")[:-1]).replace("/", "."))
                data["packages_count"] = len(packages)

                manifest_content = ""
                manifest_dict = {}
                # Parse META-INF/MANIFEST.MF
                if "META-INF/MANIFEST.MF" in namelist:
                    manifest_content = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                    data["code_preview"] = manifest_content[:15000]

                    for line in manifest_content.splitlines():
                        if ":" in line and not line.startswith(" "):
                            parts = line.split(":", 1)
                            manifest_dict[parts[0].strip().lower()] = parts[1].strip()

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

                # Scan and decompile contained .class files using JavaClassParser
                class_parsers = []
                classes_catalog = []
                all_class_names = []
                all_method_calls = []
                all_strings = []
                all_urls = set()
                suspicious_apis = []

                class_entries = [i for i in infos if i.filename.endswith(".class") and i.file_size < 5000000]
                if data.get("main_class"):
                    main_file = data["main_class"].replace(".", "/") + ".class"
                    class_entries.sort(key=lambda x: 0 if x.filename == main_file else 1)

                for info in class_entries[:500]:
                    try:
                        c_bytes = zf.read(info.filename)
                        parser = JavaClassParser(c_bytes)
                        if parser.parse():
                            class_parsers.append(parser)
                            cls_full = parser.class_name or info.filename.replace(".class", "")
                            all_class_names.append(cls_full)
                            all_method_calls.extend(parser.method_calls)
                            all_strings.extend(parser.strings)

                            joined_methods = " ".join([m["full"] for m in parser.method_calls] + parser.strings)
                            class_apis = []
                            for api_def in HIGH_RISK_JAVA_APIS:
                                if api_def["pattern"].search(joined_methods):
                                    entry = {
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
                                    }
                                    suspicious_apis.append(entry)
                                    class_apis.append(entry)

                            for s in parser.strings:
                                for u in re.findall(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', s):
                                    all_urls.add(u)

                            is_main_entry = any(m.get("is_main") for m in parser.methods) or (data.get("main_class") and data["main_class"].replace(".", "/") == cls_full.replace(".", "/"))
                            simple_n = cls_full.split("/")[-1].split(".")[-1]
                            is_obf = len(simple_n) <= 2 or (simple_n.islower() and len(simple_n) <= 3)

                            classes_catalog.append({
                                "class_name": cls_full.replace("/", "."),
                                "class_file": info.filename,
                                "simple_name": simple_n,
                                "package_name": ".".join(cls_full.replace("/", ".").split(".")[:-1]),
                                "super_class": parser.super_class_name.replace("/", "."),
                                "interfaces": [i.replace("/", ".") for i in parser.interfaces],
                                "methods_count": len(parser.methods),
                                "fields_count": len(parser.fields),
                                "methods": [m.get("signature", m.get("name") + "()") for m in parser.methods],
                                "fields": [f.get("formatted", f.get("name")) for f in parser.fields],
                                "is_main": is_main_entry,
                                "is_entry": is_main_entry,
                                "is_obfuscated": is_obf,
                                "danger_apis_count": len(class_apis),
                                "danger_apis": class_apis,
                                "decompiled_source": parser.get_decompiled_source(class_apis)
                            })
                        else:
                            c_text = c_bytes.decode("latin1", errors="ignore")
                            all_strings.append(c_text[:1000])
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
                    except Exception as e:
                        logger.debug(f"Error parsing JAR class entry {info.filename}: {e}")

                # Scan resources and text files
                for info in infos:
                    if not info.filename.endswith(".class") and info.file_size < 500000:
                        try:
                            r_bytes = zf.read(info.filename)
                            if r_bytes.startswith(b"\xca\xfe\xba\xbe"):
                                data["embedded_binaries"].append(f"{info.filename} (Hidden Compiled Class)")
                            elif r_bytes.startswith(b"PK\x03\x04") and info.filename != "META-INF/MANIFEST.MF":
                                data["embedded_binaries"].append(f"{info.filename} (Hidden Embedded ZIP/JAR)")

                            r_text = r_bytes.decode("utf-8", errors="ignore")
                            if r_text:
                                all_strings.append(r_text[:3000])
                                for u in re.findall(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', r_text):
                                    all_urls.add(u)
                        except Exception:
                            pass

                # Sort classes catalog: entry points and classes with dangerous APIs first
                classes_catalog.sort(key=lambda c: (
                    0 if c["is_main"] else 1,
                    0 if c["danger_apis_count"] > 0 else 1,
                    -c["danger_apis_count"],
                    c["class_name"]
                ))

                # Build Multi-Module Code Explorer list (like Script & Python code modules)
                code_modules = [
                    {
                        "name": "META-INF/MANIFEST.MF",
                        "code": manifest_content or "// Manifest absent or empty",
                        "language": "properties"
                    }
                ]
                for c in classes_catalog[:40]:
                    tag = " (Entry Point)" if c["is_main"] else (f" ({c['danger_apis_count']} High-Risk APIs)" if c["danger_apis_count"] > 0 else "")
                    code_modules.append({
                        "name": f"{c['class_name']}{tag}",
                        "code": c["decompiled_source"],
                        "language": "java"
                    })

                # Bundled Scripts & Configs
                for info in infos:
                    ext = Path(info.filename).suffix.lower()
                    if ext in [".bat", ".cmd", ".sh", ".ps1", ".vbs", ".py", ".js", ".properties", ".json", ".xml", ".yml", ".yaml"]:
                        try:
                            f_text = zf.read(info.filename).decode("utf-8", errors="ignore")
                            if f_text.strip():
                                lang = "bash" if ext == ".sh" else ("batch" if ext in [".bat", ".cmd"] else ("python" if ext == ".py" else ("javascript" if ext == ".js" else ("json" if ext == ".json" else "text"))))
                                code_modules.append({
                                    "name": f"{info.filename} (Resource)",
                                    "code": f_text[:100000],
                                    "language": lang
                                })
                        except Exception:
                            pass

                # Categorized Strings (like PE/ELF Binaries)
                all_sample, categorized_strings, total_str_count = self._categorize_strings(all_strings)

                # Base64 Blocks Extraction & Automatic Decoding (like Scripts / Python)
                raw_text_corpus = (
                    " ".join(namelist) + " " +
                    manifest_content + " " +
                    " ".join(all_strings) + " " +
                    " ".join([m["full"] for m in all_method_calls])
                )
                b64_blocks = self._extract_base64_blocks(raw_text_corpus, findings)

                # Add decoded Base64 blocks to code_modules
                for idx, b64 in enumerate(b64_blocks[:5]):
                    if b64.get("decoded_preview"):
                        code_modules.append({
                            "name": f"Decoded Base64 Payload #{idx+1} ({b64.get('encoding')})",
                            "code": b64.get("decoded_preview", "") + "\n\n// Full Encoded Payload:\n" + b64.get("encoded_full", ""),
                            "language": "text"
                        })

                # LOLBins & Commands
                lolbin_matches, has_lolbins, detected_commands = self._extract_lolbins_and_commands(raw_text_corpus, all_strings)

                # Digital Signature & Signer Certificate Verification (like Binaries Authenticode)
                digital_sig_status, signing_info = self._inspect_jar_signature(zf, namelist, findings)

                # Embedded Resources (like Binaries / Office)
                embedded_resources = self._inspect_embedded_resources(infos)

                # Set JAR triage compatibility fields
                data["is_jar"] = True
                data["class_count"] = data["classes_count"]
                data["manifest_content"] = manifest_content
                data["packages"] = sorted(list(packages))
                data["total_entries"] = len(namelist)
                data["suspicious_apis"] = suspicious_apis
                data["dangerous_apis"] = suspicious_apis
                data["iocs"]["urls"] = sorted(list(all_urls))[:100]

                # Parity with Scripts, Python, and Binaries:
                data["classes_decompiled"] = classes_catalog
                data["code_modules"] = code_modules
                data["strings"] = {
                    "all_sample": all_sample,
                    "categorized": categorized_strings,
                    "total_count": total_str_count
                }
                data["b64_blocks"] = b64_blocks
                data["lolbin_matches"] = lolbin_matches
                data["has_lolbins"] = has_lolbins
                data["detected_commands"] = detected_commands
                data["digital_signature"] = digital_sig_status
                data["signing_info"] = signing_info
                data["embedded_resources"] = embedded_resources

                # Comprehensive Checklist Analysis:
                # 1. Archive Structural & Integrity Security
                archive_security = self._audit_archive_security(file_path, zf, infos, findings)

                # 2. Dependencies, Shaded Libraries & CycloneDX SBOM
                dependencies, shaded_libraries, cve_advisories, cyclonedx_sbom = self._audit_dependencies_and_sbom(
                    zf, infos, namelist, manifest_dict, packages, findings
                )

                # 3. Hardcoded Secrets & CTF Flags
                secrets_and_ctf = self._scan_secrets_and_ctf(raw_text_corpus, all_strings, zf, infos, findings)

                data["archive_security"] = archive_security
                data["dependencies"] = dependencies
                data["shaded_libraries"] = shaded_libraries
                data["cve_advisories"] = cve_advisories
                data["cyclonedx_sbom"] = cyclonedx_sbom
                data["secrets_and_ctf"] = secrets_and_ctf

                # Class metadata from first valid class or main class
                if class_parsers:
                    first_cp = class_parsers[0]
                    data["class_info"] = {
                        "major_version": first_cp.major_version,
                        "minor_version": first_cp.minor_version,
                        "java_version": first_cp.java_version_name,
                        "constant_pool_count": len(first_cp.constant_pool),
                        "methods_count": len(first_cp.methods),
                        "interfaces_count": len(first_cp.interfaces)
                    }

                # Disassemble main entry class or first .class for code_preview
                if classes_catalog:
                    data["code_preview"] = (manifest_content + "\n\n" + classes_catalog[0]["decompiled_source"]).strip()

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

                # Check Java RAT signatures across manifest, filenames, and strings
                joined_all = " ".join(namelist) + " " + data.get("code_preview", "") + " " + " ".join(all_strings[:2000])
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

                # 4-Pillar Behavioral Analysis (SecurityScorecard Methodology)
                data["behavioral_analysis"] = self._audit_behavioral_capabilities(
                    strings=all_strings,
                    method_calls=all_method_calls,
                    class_names=all_class_names,
                    namelist=namelist,
                    manifest_text=manifest_content,
                    embedded_binaries=data["embedded_binaries"],
                    raw_text_corpus=raw_text_corpus,
                    iocs=data["iocs"]
                )
                data["strrat_profile"] = data["behavioral_analysis"]["strrat_heuristics"]
                self._generate_behavioral_findings(data["behavioral_analysis"], findings, data)

        except Exception as e:
            logger.debug(f"JAR analysis error: {e}")
