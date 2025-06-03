// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FixCircularLog,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FixCircularLog";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (FixCircularLog) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FixCircularLog(); 

    // O log de total_probe_calls já está dentro de execute...
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-FCLP) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]") {
            heisenbugConfirmedByLastProbe = true;
        }

        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FCLP) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.is_this_victim !== undefined) { 
                logS3(`       Na última sonda ('this' confuso), 'this' === victim? ${result.toJSON_details.is_this_victim}`, "info");
            }
            if (result.toJSON_details.is_this_prev_marker !== undefined) {
                 logS3(`       Na última sonda ('this' confuso), 'this' era o retorno da sonda anterior? ${result.toJSON_details.is_this_prev_marker}`, "info");
            }
            if (result.toJSON_details.confused_this_received_primitives) { 
                 logS3(`       Primitivas escritas no 'this' confuso: ${result.toJSON_details.confused_this_received_primitives}`, "info");
            }
            document.title = `Heisenbug (TypedArray-FCLP) TC Log OK`;
            if (result.toJSON_details && result.toJSON_details.recursion_stopped_v30) {
                document.title += ` (Probe Limit Hit)`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP) || document.title.includes("Probing")) {
            document.title = `Heisenbug (TypedArray-FCLP) TC Log Fail`;
             if (result.toJSON_details && result.toJSON_details.recursion_stopped_v30) {
                document.title += ` (Probe Limit Hit)`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (FixCircularLog) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (FixCircularLog) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("TC Log OK") && !document.title.includes("TC Log Fail") && 
            !document.title.includes("ERR")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP} Concluído`;
        }
    }
}
