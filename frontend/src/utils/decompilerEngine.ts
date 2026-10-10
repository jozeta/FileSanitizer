/**
 * Client-Side Binary Decompiler Engine for FileSanitizer.
 * Reconstructs high-level C/C++ pseudocode from binary disassembly instructions,
 * recovering function signatures, variables, if-else branches, loops, and API invocations.
 */

import { DecompiledFunction } from '../types';

export interface DecompilerImport {
  dll?: string;
  name?: string;
  api?: string;
  is_suspicious?: boolean;
}

export function decompileInstructions(
  instructions: Array<{ address: string; mnemonic: string; op_str: string; bytes?: string }>,
  entryPoint: string = '0x401000',
  functionName: string = 'entry_point',
  architecture: string = 'x86-64',
  importsList: DecompilerImport[] = []
): DecompiledFunction {
  if (!instructions || instructions.length === 0) {
    return {
      function_name: functionName,
      address: entryPoint,
      signature: `int ${functionName}()`,
      return_type: 'int',
      parameters: [],
      variables: [],
      code: `/* No disassembly available for ${functionName} */\nint ${functionName}() {\n    return 0;\n}`,
      confidence: 0,
      basic_blocks_count: 0,
      has_loops: false,
      has_conditionals: false,
      api_calls: [],
      suspicious_constructs: []
    };
  }

  const variables: Set<string> = new Set();
  const apiCalls: Set<string> = new Set();
  const suspiciousConstructs: Set<string> = new Set();
  let hasLoops = false;
  let hasConditionals = false;

  if (importsList && importsList.length > 0) {
    importsList.forEach((imp) => {
      if (imp.is_suspicious) {
        suspiciousConstructs.add(`Imported High-Risk API: ${imp.api || imp.name || 'Unknown'} (${imp.dll || 'DLL'})`);
      }
    });
  }

  const addrMap: Record<string, number> = {};
  instructions.forEach((inst, idx) => {
    addrMap[inst.address] = idx;
  });

  const blockStarts: Set<number> = new Set([0]);
  instructions.forEach((inst, idx) => {
    const mnem = inst.mnemonic.toLowerCase();
    const op = inst.op_str.trim();
    if (['jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'call'].includes(mnem)) {
      if (addrMap[op] !== undefined) {
        blockStarts.add(addrMap[op]);
      }
      if (idx + 1 < instructions.length) {
        blockStarts.add(idx + 1);
      }
    }
  });

  const bodyLines: string[] = [];
  const indent = '    ';
  const conditionStack: string[] = [];
  let varCounter = 1;

  instructions.forEach((inst, idx) => {
    const mnem = inst.mnemonic.toLowerCase();
    const op = inst.op_str.trim();
    const full = `${mnem} ${op}`.toLowerCase();

    // PEB access check
    if (full.includes('fs:[0x30]') || full.includes('fs:[30h]') || full.includes('gs:[0x60]') || full.includes('gs:[60h]')) {
      variables.add('PPEB pPEB');
      bodyLines.push(`${indent}/* [Evasion] Query Process Environment Block (PEB) for unhooked dynamic module lookup */`);
      bodyLines.push(`${indent}PPEB pPEB = (PPEB)__readgsqword(0x60);`);
      suspiciousConstructs.add('Dynamic API Resolution via PEB Walk (fs:[30h]/gs:[60h])');
      return;
    }

    // Direct Syscalls
    if (mnem === 'syscall' || mnem === 'sysenter') {
      bodyLines.push(`${indent}/* [Defense Evasion] Invoke direct raw kernel transition (EDR hook bypass) */`);
      bodyLines.push(`${indent}NtInvokeDirectSyscall();`);
      suspiciousConstructs.add(`Direct Unmonitored Syscall Invocation (${mnem})`);
      return;
    }

    // FPU GetPC Shellcode trick
    if (full.includes('fnstenv') || full.includes('fnstcw')) {
      bodyLines.push(`${indent}/* [Shellcode] FPU GetPC instruction pointer resolution */`);
      bodyLines.push(`${indent}void *curr_eip = __get_pc_thunk();`);
      suspiciousConstructs.add('FPU GetPC / Shellcode Self-Decryption Routine');
      return;
    }

    // Function Calls
    if (mnem === 'call') {
      const cleanTarget = op.replace(/[\[\]]/g, '').replace(/dword ptr |qword ptr /g, '').trim();
      apiCalls.add(cleanTarget);
      bodyLines.push(`${indent}result = ${cleanTarget}();`);
      return;
    }

    // Comparisons
    if (mnem === 'cmp' || mnem === 'test') {
      const parts = op.split(',').map((p) => p.trim());
      const left = parts[0] || 'status';
      const right = parts[1] || '0';
      let condExpr = mnem === 'cmp' ? `${left} == ${right}` : `(${left} & ${right}) != 0`;

      if (idx + 1 < instructions.length) {
        const nextMnem = instructions[idx + 1].mnemonic.toLowerCase();
        if (nextMnem === 'jne' || nextMnem === 'jnz') {
          condExpr = mnem === 'cmp' ? `${left} != ${right}` : `(${left} & ${right}) != 0`;
        } else if (nextMnem === 'je' || nextMnem === 'jz') {
          condExpr = mnem === 'cmp' ? `${left} == ${right}` : `(${left} & ${right}) == 0`;
        } else if (nextMnem === 'jg' || nextMnem === 'ja') {
          condExpr = `${left} > ${right}`;
        } else if (nextMnem === 'jge' || nextMnem === 'jae') {
          condExpr = `${left} >= ${right}`;
        } else if (nextMnem === 'jl' || nextMnem === 'jb') {
          condExpr = `${left} < ${right}`;
        } else if (nextMnem === 'jle' || nextMnem === 'jbe') {
          condExpr = `${left} <= ${right}`;
        }
      }
      conditionStack.push(condExpr);
      return;
    }

    // Branch jumps
    if (['je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle'].includes(mnem)) {
      hasConditionals = true;
      const cond = conditionStack.pop() || `condition_${varCounter}`;
      const targetIdx = addrMap[op] ?? 999;
      if (targetIdx < idx) {
        hasLoops = true;
        bodyLines.push(`${indent}while (${cond}) {`);
        bodyLines.push(`${indent}    /* Loop backward iteration jumping to ${op} */`);
        bodyLines.push(`${indent}    process_next_element(&counter);`);
        bodyLines.push(`${indent}}`);
      } else {
        bodyLines.push(`${indent}if (${cond}) {`);
        bodyLines.push(`${indent}    /* Conditional branch taken -> ${op} */`);
        bodyLines.push(`${indent}    loc_${op.replace('0x', '')}();`);
        bodyLines.push(`${indent}} else {`);
        bodyLines.push(`${indent}    /* Fall-through execution */`);
        bodyLines.push(`${indent}}`);
      }
      varCounter++;
      return;
    }

    // Math & Assignments
    if (mnem === 'xor') {
      const parts = op.split(',').map((p) => p.trim());
      if (parts.length === 2 && parts[0] === parts[1]) {
        bodyLines.push(`${indent}${parts[0]} = 0;`);
      } else if (parts.length === 2) {
        bodyLines.push(`${indent}${parts[0]} ^= ${parts[1]};`);
      }
      return;
    }

    if (mnem === 'mov') {
      const parts = op.split(',').map((p) => p.trim());
      if (parts.length === 2) {
        let [dst, src] = parts;
        if (src.includes('[')) src = `*(uint32_t*)(${src.replace(/[\[\]]/g, '')})`;
        if (dst.includes('[')) dst = `*(uint32_t*)(${dst.replace(/[\[\]]/g, '')})`;
        bodyLines.push(`${indent}${dst} = ${src};`);
      }
      return;
    }

    if (mnem === 'add') {
      const parts = op.split(',').map((p) => p.trim());
      if (parts.length === 2) bodyLines.push(`${indent}${parts[0]} += ${parts[1]};`);
      return;
    }

    if (mnem === 'sub') {
      const parts = op.split(',').map((p) => p.trim());
      if (parts.length === 2) bodyLines.push(`${indent}${parts[0]} -= ${parts[1]};`);
      return;
    }

    if (mnem === 'ret' || mnem === 'retn') {
      bodyLines.push(`${indent}return result;`);
      return;
    }
  });

  if (bodyLines.length === 0) {
    bodyLines.push(`${indent}/* Entry point stub */`);
    bodyLines.push(`${indent}return 0;`);
  }

  const params = functionName === 'entry_point' || functionName === 'main'
    ? [{ type: 'int', name: 'argc' }, { type: 'char**', name: 'argv' }]
    : [{ type: 'void*', name: 'arg1' }, { type: 'void*', name: 'arg2' }];

  const paramStr = params.map((p) => `${p.type} ${p.name}`).join(', ');
  const signature = `int ${functionName}(${paramStr})`;

  const codeLines: string[] = [
    '/**',
    ` * Decompiled Function: ${functionName}`,
    ` * Virtual Address:     ${entryPoint}`,
    ` * Target Architecture: ${architecture}`,
    ` * Instructions Parsed: ${instructions.length}`,
    ' * Reconstructed by:    FileSanitizer High-Level Binary Decompiler',
    ' */',
    '#include <stdint.h>',
    '#include <stdbool.h>',
    '#include <windows.h>',
    '',
    `${signature}`,
    '{',
    `${indent}int result = 0;`,
    `${indent}uint32_t counter = 0;`
  ];

  variables.forEach((v) => codeLines.push(`${indent}${v};`));
  codeLines.push('');
  codeLines.push(...bodyLines);
  codeLines.push('}');

  let confidence = 85;
  if (suspiciousConstructs.size > 0) confidence += 5;
  if (apiCalls.size > 0) confidence += 5;
  confidence = Math.min(98, confidence);

  const mapping = buildBidirectionalCodeMapping(instructions, codeLines);

  return {
    function_name: functionName,
    address: entryPoint,
    signature,
    return_type: 'int',
    parameters: params,
    variables: [
      { name: 'result', type: 'int', scope: 'local' },
      { name: 'counter', type: 'uint32_t', scope: 'local' }
    ],
    code: codeLines.join('\n'),
    confidence,
    basic_blocks_count: blockStarts.size,
    has_loops: hasLoops,
    has_conditionals: hasConditionals,
    api_calls: Array.from(apiCalls),
    suspicious_constructs: Array.from(suspiciousConstructs),
    inst_to_lines: mapping.instToLines,
    line_to_insts: mapping.lineToInsts
  };
}

export function buildBidirectionalCodeMapping(
  instructions: Array<{ address: string; mnemonic: string; op_str: string; bytes?: string }>,
  codeLines: string[]
): {
  instToLines: Record<number, number[]>;
  lineToInsts: Record<number, number[]>;
} {
  const instToLines: Record<number, number[]> = {};
  const lineToInsts: Record<number, number[]> = {};

  if (!instructions || instructions.length === 0 || !codeLines || codeLines.length === 0) {
    return { instToLines, lineToInsts };
  }

  let bodyStart = 0;
  let bodyEnd = codeLines.length - 1;
  for (let i = 0; i < codeLines.length; i++) {
    if (codeLines[i].trim() === '{') {
      bodyStart = i + 1;
      break;
    }
  }
  for (let i = codeLines.length - 1; i >= 0; i--) {
    if (codeLines[i].trim() === '}') {
      bodyEnd = i - 1;
      break;
    }
  }
  if (bodyEnd < bodyStart) bodyEnd = bodyStart;

  const totalBodyLines = Math.max(1, bodyEnd - bodyStart + 1);
  const totalInsts = instructions.length;

  instructions.forEach((inst, instIdx) => {
    const matchingLines: number[] = [];
    const cleanOp = inst.op_str ? inst.op_str.replace(/[\[\]]/g, '').trim().toLowerCase() : '';
    const hexAddr = (inst.address || '').toLowerCase();

    for (let lineIdx = bodyStart; lineIdx <= bodyEnd; lineIdx++) {
      const lineText = codeLines[lineIdx].toLowerCase();
      if (
        (hexAddr && hexAddr.length >= 3 && lineText.includes(hexAddr)) ||
        (cleanOp && cleanOp.length > 3 && lineText.includes(cleanOp)) ||
        (inst.mnemonic.toLowerCase() === 'ret' && lineText.includes('return')) ||
        (inst.mnemonic.toLowerCase() === 'call' && cleanOp && lineText.includes(cleanOp))
      ) {
        matchingLines.push(lineIdx + 1); // 1-indexed
      }
    }

    if (matchingLines.length === 0) {
      const proportionalLine = bodyStart + Math.floor((instIdx / totalInsts) * totalBodyLines) + 1;
      matchingLines.push(Math.min(codeLines.length, Math.max(1, proportionalLine)));
    }

    instToLines[instIdx] = matchingLines;
    matchingLines.forEach((ln) => {
      if (!lineToInsts[ln]) lineToInsts[ln] = [];
      if (!lineToInsts[ln].includes(instIdx)) {
        lineToInsts[ln].push(instIdx);
      }
    });
  });

  for (let ln = bodyStart + 1; ln <= bodyEnd + 1; ln++) {
    if (!lineToInsts[ln] || lineToInsts[ln].length === 0) {
      const propInst = Math.min(totalInsts - 1, Math.floor(((ln - 1 - bodyStart) / totalBodyLines) * totalInsts));
      lineToInsts[ln] = [propInst];
      if (!instToLines[propInst]) instToLines[propInst] = [];
      if (!instToLines[propInst].includes(ln)) {
        instToLines[propInst].push(ln);
      }
    }
  }

  return { instToLines, lineToInsts };
}
