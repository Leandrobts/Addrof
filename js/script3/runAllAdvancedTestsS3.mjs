// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FixProbeCapture,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FixProbeCapture";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (FixProbeCapture) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FixProbeCapture(); 

    // O log do total de chamadas da sonda já está dentro de executeTypedArrayVictimAddrofTest_FixProbeCapture
    // e o result.total_probe_calls será 0 devido ao reset no finally.

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-FPC) ERR: ${result.errorOccurred.name}`;
    } else if (result.potentiallyCrashed) { 
         logS3(`   RESULTADO: POTENCIAL ESTOURO DE PILHA. Detalhes da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         document.title = `Heisenbug (TypedArray-FPC) StackOverflow?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados externamente): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FPC) toJSON_ERR`;
        } else if (result.heisenbug_confirmed_via_capture) {
            logS3(`     !!!! HEISENBUG CONFIRMADA EXTERNAMENTE !!!! 'this' type na última sonda capturada: ${result.toJSON_details.this_type_in_toJSON}`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FPC) TC Confirmed`;
        } else {
            logS3(`     Heisenbug NÃO confirmada externamente. Último tipo de 'this' capturado: ${result.toJSON_details ? result.toJSON_details.this_type_in_toJSON : 'N/A'}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FPC) TC Not Confirmed`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (FixProbeCapture) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Corrigindo Captura de Detalhes da Sonda ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("Confirmed") && // Abrange "TC Confirmed" e "TC NOT Confirmed"
            !document.title.includes("ERR")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC} Concluído`;
        }
    }
}
