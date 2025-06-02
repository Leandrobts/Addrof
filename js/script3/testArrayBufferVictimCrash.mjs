// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FocusOnConfusedThis_FixError, // ATUALIZADO para _FixError
    FNAME_MODULE_TYPEDARRAY_ADDROF_V4_FOCUS_CT_FE                 // ATUALIZADO para _FE
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FocusOnConfusedThis_FixError"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (FocusOnConfusedThis_FixError) ====`, 'test', FNAME_RUNNER); 

    const result = await executeTypedArrayVictimAddrofTest_FocusOnConfusedThis_FixError();  

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FCT-FE) RangeError!`; 
         } else {
            document.title = `Heisenbug (TypedArray-FCT-FE) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-FCT-FE) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        
        let heisenbugObservedInProbe = false;
        if (result.toJSON_details && result.toJSON_details.probe_called && 
            result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            heisenbugObservedInProbe = true;
        }

        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A SUCESSO! ${result.addrof_A_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A FALHOU: ${result.addrof_A_attempt_result.message}`, heisenbugObservedInProbe ? "warn" : "error", FNAME_RUNNER);
        }
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B SUCESSO! ${result.addrof_B_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B FALHOU: ${result.addrof_B_attempt_result.message}`, heisenbugObservedInProbe ? "warn" : "error", FNAME_RUNNER);
        }

        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FCT-FE) toJSON_ERR`;
        } else if (heisenbugObservedInProbe) {
            logS3(`     !!!! TYPE CONFUSION OBSERVADA NA SONDA !!!! Tipo de 'this' na última sonda: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
             if (result.toJSON_details.this_was_victim_ref_when_confused !== null) { 
                logS3(`       Na última sonda confusa, 'this' === victim_typed_array_ref_v4fct? ${result.toJSON_details.this_was_victim_ref_when_confused}`, "info");
            }
            if (result.toJSON_details.writes_attempted_on_confused_this) { 
                 logS3(`       Escritas addrof tentadas no 'this' confuso: ${result.toJSON_details.writes_attempted_on_confused_this}`, "info");
            }
            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-FCT-FE) TYPE CONFUSION`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V4_FOCUS_CT_FE) || document.title.includes("Probing")) { 
            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-FCT-FE) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima (FocusOnConfusedThis_FixError) CONCLUÍDA ====`, 'test', FNAME_RUNNER); 
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_FOCUS_CT_FE}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (FocusOnConfusedThis_FixError) ====`, 'test', FNAME_ORCHESTRATOR); 

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V4_FOCUS_CT_FE)) { 
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_FOCUS_CT_FE} Concluído`; 
        }
    }
}
