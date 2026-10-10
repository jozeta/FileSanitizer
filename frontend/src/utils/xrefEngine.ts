/**
 * Client-Side Cross-References (XREFs) Utility for FileSanitizer.
 * Synthesizes or looks up code and data cross-references for any symbol, function, or string.
 */

import { XrefData, XrefEntry } from '../types';

export function buildClientXrefs(
  instructions: Array<{ address: string; mnemonic: string; op_str: string }>,
  knownStrings: Array<{ offset?: string; value: string }> = [],
  importedApis: Array<{ api?: string; name?: string }> = []
): XrefData {
  const targetToXrefs: Record<string, XrefEntry[]> = {};
  const sourceToOutgoing: Record<string, XrefEntry[]> = {};
  let codeCount = 0;
  let dataCount = 0;
  let stringCount = 0;

  const stringMap: Record<string, string> = {};
  knownStrings.forEach((s) => {
    if (s.offset && s.value) {
      stringMap[s.offset.toLowerCase()] = s.value;
    }
  });

  const apiNames = new Set<string>();
  importedApis.forEach((imp) => {
    const n = imp.api || imp.name;
    if (n) apiNames.add(n.toLowerCase());
  });

  const addIncoming = (targetKey: string, entry: XrefEntry) => {
    const k = targetKey.trim().toLowerCase();
    if (!k) return;
    if (!targetToXrefs[k]) targetToXrefs[k] = [];
    targetToXrefs[k].push(entry);
  };

  const addOutgoing = (srcKey: string, entry: XrefEntry) => {
    const k = srcKey.trim().toLowerCase();
    if (!k) return;
    if (!sourceToOutgoing[k]) sourceToOutgoing[k] = [];
    sourceToOutgoing[k].push(entry);
  };

  let currentFunction = 'entry_point';
  const callMnemonics = new Set(['call']);
  const jumpMnemonics = new Set(['jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle']);
  const hexRegex = /0x[0-9a-fA-F]+/g;
  const memRegex = /\[([^\]]+)\]/g;

  instructions.forEach((inst, idx) => {
    const addr = inst.address;
    const mnem = inst.mnemonic.toLowerCase();
    const op = inst.op_str;
    const rawInst = `${mnem} ${op}`;

    if (mnem === 'push' && (op.includes('ebp') || op.includes('rbp')) && idx > 0) {
      currentFunction = `sub_${addr.replace('0x', '')}`;
    }

    // 1. Calls
    if (callMnemonics.has(mnem)) {
      const cleanTarget = op.replace(/[\[\]]/g, '').replace(/dword ptr |qword ptr /g, '').trim();
      const isApi = apiNames.has(cleanTarget.toLowerCase());
      const entry: XrefEntry = {
        from_address: addr,
        from_function: currentFunction,
        target: cleanTarget,
        instruction: rawInst,
        ref_type: isApi ? 'API_CALL' : 'CODE_CALL',
        direction: 'incoming',
        description: `Call to ${cleanTarget} from ${currentFunction}`
      };
      addIncoming(cleanTarget, entry);
      addIncoming(addr, entry);
      addOutgoing(currentFunction, { ...entry, direction: 'outgoing' });
      codeCount++;
      return;
    }

    // 2. Jumps
    if (jumpMnemonics.has(mnem)) {
      const cleanTarget = op.trim();
      const entry: XrefEntry = {
        from_address: addr,
        from_function: currentFunction,
        target: cleanTarget,
        instruction: rawInst,
        ref_type: mnem === 'jmp' ? 'UNCONDITIONAL_JUMP' : 'CONDITIONAL_JUMP',
        direction: 'incoming',
        description: `Branch jump (${mnem.toUpperCase()}) to ${cleanTarget}`
      };
      addIncoming(cleanTarget, entry);
      addOutgoing(currentFunction, { ...entry, direction: 'outgoing' });
      codeCount++;
      return;
    }

    // 3. String References
    const hexMatches = op.match(hexRegex) || [];
    let matchedString: { addr: string; val: string } | null = null;
    for (const h of hexMatches) {
      const hl = h.toLowerCase();
      if (stringMap[hl]) {
        matchedString = { addr: h, val: stringMap[hl] };
        break;
      }
    }

    if (matchedString) {
      const entry: XrefEntry = {
        from_address: addr,
        from_function: currentFunction,
        target: matchedString.val,
        target_address: matchedString.addr,
        instruction: rawInst,
        ref_type: 'STRING_REF',
        direction: 'incoming',
        description: `String reference: "${matchedString.val.substring(0, 28)}"`
      };
      addIncoming(matchedString.val, entry);
      addIncoming(matchedString.addr, entry);
      addOutgoing(currentFunction, { ...entry, direction: 'outgoing' });
      stringCount++;
      dataCount++;
      return;
    }

    // 4. Data Reads / Writes
    const memMatches = op.match(memRegex);
    if (memMatches || (['lea', 'mov'].includes(mnem) && hexMatches.length > 0)) {
      const refType = mnem === 'mov' && op.startsWith('[') ? 'DATA_WRITE' : 'DATA_READ';
      const targetSym = memMatches ? memMatches[0] : hexMatches[0];
      if (targetSym) {
        const entry: XrefEntry = {
          from_address: addr,
          from_function: currentFunction,
          target: targetSym,
          instruction: rawInst,
          ref_type: refType,
          direction: 'incoming',
          description: `Memory ${refType.toLowerCase().replace('_', ' ')}: ${targetSym}`
        };
        addIncoming(targetSym, entry);
        addOutgoing(currentFunction, { ...entry, direction: 'outgoing' });
        dataCount++;
      }
    }
  });

  const hotspots = Object.entries(targetToXrefs)
    .filter(([_, list]) => list.length >= 2)
    .map(([target, list]) => ({
      target,
      references_count: list.length,
      callers: Array.from(new Set(list.map((e) => e.from_function)))
    }))
    .sort((a, b) => b.references_count - a.references_count)
    .slice(0, 15);

  return {
    total_xrefs: codeCount + dataCount,
    code_xrefs_count: codeCount,
    data_xrefs_count: dataCount,
    string_xrefs_count: stringCount,
    target_to_xrefs: targetToXrefs,
    source_to_outgoing: sourceToOutgoing,
    hotspots
  };
}

export function lookupXrefsForSymbol(xrefsData: XrefData | undefined, symbol: string): XrefEntry[] {
  if (!xrefsData || !xrefsData.target_to_xrefs || !symbol) return [];
  const clean = symbol.trim().toLowerCase();
  return xrefsData.target_to_xrefs[clean] || [];
}
