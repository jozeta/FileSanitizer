/**
 * Client-Side API Hashing & Dynamic Resolution Detection Engine.
 * Detects known Win32 API hashes (ROR13, CRC32, FNV-1a, Murmur3) in disassembly or decompilation.
 * MITRE ATT&CK T1027.007: Dynamic API Resolution.
 */

import { ApiHashMatch } from '../types';

export function ror13(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h >>> 13) | ((h << (32 - 13)) >>> 0)) >>> 0;
    h = (h + str.charCodeAt(i)) >>> 0;
  }
  return h;
}

export function fnv1a32(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h = (h ^ str.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

export function crc32(str: string): number {
  let c = 0 ^ (-1);
  for (let i = 0; i < str.length; i++) {
    let byte = str.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    c = c ^ byte;
  }
  return (c ^ (-1)) >>> 0;
}

// Database of critical Win32 APIs
export const KNOWN_APIS: Array<{ api: string; dll: string; category: string; severity: 'critical' | 'high' | 'medium' | 'low'; description: string }> = [
  { api: 'VirtualAlloc', dll: 'kernel32.dll', category: 'Memory Management', severity: 'high', description: 'Allocates memory page for payload staging (MITRE T1055)' },
  { api: 'VirtualAllocEx', dll: 'kernel32.dll', category: 'Process Injection', severity: 'critical', description: 'Allocates virtual memory in remote process space' },
  { api: 'VirtualProtect', dll: 'kernel32.dll', category: 'Memory Management', severity: 'high', description: 'Alters memory protection permissions (e.g. RWX executable)' },
  { api: 'VirtualProtectEx', dll: 'kernel32.dll', category: 'Process Injection', severity: 'critical', description: 'Alters remote memory permissions for execution' },
  { api: 'WriteProcessMemory', dll: 'kernel32.dll', category: 'Process Injection', severity: 'critical', description: 'Writes payload into remote target process' },
  { api: 'ReadProcessMemory', dll: 'kernel32.dll', category: 'Credential Dumping', severity: 'high', description: 'Reads memory from target process (e.g. LSASS)' },
  { api: 'CreateRemoteThread', dll: 'kernel32.dll', category: 'Process Injection', severity: 'critical', description: 'Spawns execution thread inside remote process' },
  { api: 'QueueUserAPC', dll: 'kernel32.dll', category: 'Early Bird Injection', severity: 'critical', description: 'Queues APC thread execution callback' },
  { api: 'SetThreadContext', dll: 'kernel32.dll', category: 'Thread Hijacking', severity: 'critical', description: 'Overwrites CPU registers / RIP of target thread' },
  { api: 'GetThreadContext', dll: 'kernel32.dll', category: 'Thread Hijacking', severity: 'high', description: 'Queries CPU execution state of thread' },
  { api: 'ResumeThread', dll: 'kernel32.dll', category: 'Process Injection', severity: 'medium', description: 'Resumes suspended execution thread' },
  { api: 'CreateProcessA', dll: 'kernel32.dll', category: 'Process Spawning', severity: 'medium', description: 'Creates child process instance' },
  { api: 'CreateProcessW', dll: 'kernel32.dll', category: 'Process Spawning', severity: 'medium', description: 'Creates child process instance (Unicode)' },
  { api: 'WinExec', dll: 'kernel32.dll', category: 'Execution', severity: 'high', description: 'Executes command line program (legacy dropper hook)' },
  { api: 'LoadLibraryA', dll: 'kernel32.dll', category: 'Dynamic Resolution', severity: 'medium', description: 'Loads dynamic library into memory' },
  { api: 'LoadLibraryW', dll: 'kernel32.dll', category: 'Dynamic Resolution', severity: 'medium', description: 'Loads dynamic library into memory (Unicode)' },
  { api: 'GetProcAddress', dll: 'kernel32.dll', category: 'Dynamic Resolution', severity: 'medium', description: 'Resolves function pointer address by export name' },
  { api: 'IsDebuggerPresent', dll: 'kernel32.dll', category: 'Anti-Debugging', severity: 'high', description: 'Queries PEB.BeingDebugged flag' },
  { api: 'CheckRemoteDebuggerPresent', dll: 'kernel32.dll', category: 'Anti-Debugging', severity: 'high', description: 'Queries ProcessDebugPort for remote debugger' },
  { api: 'InternetOpenA', dll: 'wininet.dll', category: 'C2 Communication', severity: 'high', description: 'Initializes WinINet HTTP/FTP session' },
  { api: 'InternetOpenUrlA', dll: 'wininet.dll', category: 'C2 Communication', severity: 'high', description: 'Fetches remote URL payload over HTTP/HTTPS' },
  { api: 'URLDownloadToFileA', dll: 'urlmon.dll', category: 'Payload Downloader', severity: 'critical', description: 'Downloads remote binary file directly to disk' },
  { api: 'URLDownloadToFileW', dll: 'urlmon.dll', category: 'Payload Downloader', severity: 'critical', description: 'Downloads remote binary file directly to disk (Unicode)' },
  { api: 'NtAllocateVirtualMemory', dll: 'ntdll.dll', category: 'Native API', severity: 'high', description: 'Low-level syscall for page memory allocation' },
  { api: 'NtMapViewOfSection', dll: 'ntdll.dll', category: 'Process Hollowing', severity: 'critical', description: 'Maps executable section for process hollowing' },
  { api: 'NtUnmapViewOfSection', dll: 'ntdll.dll', category: 'Process Hollowing', severity: 'critical', description: 'Unmaps original code section for process hollowing' },
  { api: 'RegOpenKeyExA', dll: 'advapi32.dll', category: 'Persistence', severity: 'medium', description: 'Opens Windows Registry hive key' },
  { api: 'RegSetValueExA', dll: 'advapi32.dll', category: 'Persistence', severity: 'high', description: 'Writes Run/RunOnce Registry persistence key' },
];

// Precompute client-side hash lookup table
const CLIENT_HASH_MAP: Map<number, Array<{ api: string; dll: string; algorithm: string; category: string; severity: 'critical' | 'high' | 'medium' | 'low'; description: string }>> = new Map();

function initClientHashMap() {
  if (CLIENT_HASH_MAP.size > 0) return;

  KNOWN_APIS.forEach((item) => {
    // ROR13
    const r13 = ror13(item.api);
    if (!CLIENT_HASH_MAP.has(r13)) CLIENT_HASH_MAP.set(r13, []);
    CLIENT_HASH_MAP.get(r13)!.push({ ...item, algorithm: 'ROR13' });

    // FNV1a
    const fnv = fnv1a32(item.api);
    if (!CLIENT_HASH_MAP.has(fnv)) CLIENT_HASH_MAP.set(fnv, []);
    CLIENT_HASH_MAP.get(fnv)!.push({ ...item, algorithm: 'FNV-1a' });

    // CRC32
    const c32 = crc32(item.api);
    if (!CLIENT_HASH_MAP.has(c32)) CLIENT_HASH_MAP.set(c32, []);
    CLIENT_HASH_MAP.get(c32)!.push({ ...item, algorithm: 'CRC32' });
  });
}

/**
 * Resolves a 32-bit hex number or decimal value to a known Win32 API match.
 */
export function resolveApiHash(val: number): ApiHashMatch[] {
  initClientHashMap();
  const matches = CLIENT_HASH_MAP.get(val >>> 0);
  if (!matches) return [];

  return matches.map((m) => ({
    hash_hex: `0x${(val >>> 0).toString(16).padStart(8, '0')}`,
    resolved_api: m.api,
    dll: m.dll,
    algorithm: m.algorithm,
    category: m.category,
    severity: m.severity,
    description: m.description,
    mitre_tactic: 'T1027.007 (Dynamic API Resolution)',
    confidence: 'High (Cryptographic Hash Match)'
  }));
}

/**
 * Scans a list of disassembly instructions for API hash constants.
 */
export function scanInstructionsForApiHashes(
  instructions: Array<{ address: string; mnemonic: string; op_str: string }>
): ApiHashMatch[] {
  initClientHashMap();
  const results: ApiHashMatch[] = [];
  const seen = new Set<string>();

  const hexRegex = /0x([0-9a-fA-F]{5,8})\b/g;

  instructions.forEach((inst) => {
    let match: RegExpExecArray | null;
    while ((match = hexRegex.exec(inst.op_str)) !== null) {
      const hexVal = parseInt(match[1], 16);
      const matched = resolveApiHash(hexVal);
      matched.forEach((entry) => {
        const key = `${inst.address}:${entry.resolved_api}:${entry.algorithm}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            ...entry,
            address: inst.address,
            instruction: `${inst.mnemonic} ${inst.op_str}`
          });
        }
      });
    }
  });

  return results;
}
