// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_IsolateVictimInteraction,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_IsolateVictimInteraction";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (IsolateVictimInteraction) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_IsolateVictimInteraction(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-IVI) RangeError!`; // IVI para IsolateVictimInteraction
         } else {
            document.title = `Heisenbug (TypedArray-IVI) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-IVI) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        
        let heisenbugObservedOnThisInProbe = false; // Se o 'this' da sonda foi confundido
        if (result.toJSON_details && result.toJSON_details.probe_called && 
            result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            heisenbugObservedOnThisInProbe = true;
        }

        // Logs para addrof
        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A SUCESSO! ${result.addrof_A_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A FALHOU: ${result.addrof_A_attempt_result.message}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B SUCESSO! ${result.addrof_B_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B FALHOU: ${result.addrof_B_attempt_result.message}`, "warn", FNAME_RUNNER);
        }

        // Lógica de título e logs baseada no sucesso do addrof e observação da Heisenbug
        if (result.addrof_A_attempt_result && (result.addrof_A_attempt_result.success || result.addrof_B_attempt_result.success)) {
            // Sucesso no Addrof já define o título
        } else if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-IVI) toJSON_ERR`;
        } else if (heisenbugObservedOnThisInProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA SONDA OBSERVADA !!!! Tipo: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
             if (result.toJSON_details.this_was_victim_ref_when_confused !== null) { 
                logS3(`       Na sonda confusa, 'this' === victim_typed_array_ref_v7? ${result.toJSON_details.this_was_victim_ref_when_confused}`, "info");
            }
            if (result.toJSON_details.writes_to_original_victim_attempted !== null) { 
                 logS3(`       Escritas na VÍTIMA ORIGINAL (victim_typed_array_ref_v7) tentadas: ${result.toJSON_details.writes_to_original_victim_attempted}`, "info");
            }
            document.title = `Heisenbug (TypedArray-IVI) Sonda OK, Addr Falhou`;
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI) || document.title.includes("Probing")) {
            document.title = `Heisenbug (TypedArray-IVI) Test OK`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima (IsolateVictimInteraction) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (IsolateVictimInteraction) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI} Concluído`;
        }
    }
}
