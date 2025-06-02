// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ReliableLogging,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V5_RL    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';     // O NOME DO ARQUIVO É MANTIDO CONFORME SEU USO

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ReliableLogging"; // Nome do runner atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ReliableLogging) ====`, 'test', FNAME_RUNNER);  // Mensagem atualizada

    const result = await executeTypedArrayVictimAddrofTest_ReliableLogging(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-RL) RangeError!`; // RL para ReliableLogging
         } else {
            document.title = `Heisenbug (TypedArray-RL) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL (nenhum erro JS capturado). Detalhes da toJSON (se chamada): ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-RL) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-RL) toJSON_ERR`;
        } else if (result.toJSON_details && result.toJSON_details.probe_called && 
                    result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            logS3(`     !!!! TYPE CONFUSION DETECTADA !!!! Tipo de 'this' na última sonda: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
             if (result.toJSON_details.this_was_victim_ref_when_confused !== null) { // Nome da propriedade atualizado
                logS3(`       Na última sonda confusa, 'this' === victim_typed_array_ref_v5? ${result.toJSON_details.this_was_victim_ref_when_confused}`, "info");
            }
            if (result.toJSON_details.writes_attempted_on_confused_this) {
                 logS3(`       Escritas addrof tentadas no 'this' confuso: ${result.toJSON_details.writes_attempted_on_confused_this}`, "info");
            }
            document.title = `Heisenbug (TypedArray-RL) TYPE CONFUSION!`;
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V5_RL) || document.title.includes("Probing")) {
            document.title = `Heisenbug (TypedArray-RL) Test OK`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ReliableLogging) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V5_RL}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ReliableLogging) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V5_RL)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V5_RL} Concluído`;
        }
    }
}
