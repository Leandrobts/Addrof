// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ReFocusOnThisConfusedObject,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ReFocusOnThisConfusedObject";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ReFocusOnThisConfusedObject) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ReFocusOnThisConfusedObject(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-RFCTO) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]") { // Corrigido para this_type
            heisenbugConfirmedByLastProbe = true;
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A SUCESSO! ${result.addrof_A_attempt_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A FALHOU: ${result.addrof_A_attempt_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B SUCESSO! ${result.addrof_B_attempt_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B FALHOU: ${result.addrof_B_attempt_result.msg}`, "warn", FNAME_RUNNER);
        }


        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-RFCTO) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.this_is_victim_array !== undefined) { 
                logS3(`       Na última sonda ('this' confuso), 'this' === victim? ${result.toJSON_details.this_is_victim_array}`, "info");
            }
            if (result.toJSON_details.this_is_prev_probe_return_marker !== undefined) {
                 logS3(`       Na última sonda ('this' confuso), 'this' era o retorno da sonda anterior (call #${result.toJSON_details.prev_probe_call_marker_val})? ${result.toJSON_details.this_is_prev_probe_return_marker}`, "info");
            }
            if (result.toJSON_details.writes_on_confused_this_attempted) { 
                 logS3(`       Escritas addrof tentadas no 'this' confuso: ${result.toJSON_details.writes_on_confused_this_attempted}`, "info");
            }
             if (result.toJSON_details.writes_on_this_victim_ref_attempted) { 
                 logS3(`       Escritas na VÍTIMA ORIGINAL (via this.victim_in_marker) tentadas: ${result.toJSON_details.writes_on_this_victim_ref_attempted}`, "info");
            }

            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RFCTO) Sonda OK, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-RFCTO) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RFCTO) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ReFocusOnThisConfusedObject) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ReFocusOnThisConfusedObject) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Sonda OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO} Concluído`;
        }
    }
}
