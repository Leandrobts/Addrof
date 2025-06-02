// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_VerifyGlobalProbeDetailsCapture,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_VerifyGlobalProbeDetailsCapture";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (VerifyGlobalProbeDetailsCapture) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_VerifyGlobalProbeDetailsCapture(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-VGPDC) RangeError!`; 
         } else {
            document.title = `Heisenbug (TypedArray-VGPDC) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-VGPDC) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados externamente): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (truncado): ${result.stringifyResult ? result.stringifyResult.substring(0, 200) + "..." : 'N/A'}`, "info", FNAME_RUNNER);
        
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-VGPDC) toJSON_ERR`;
        } else if (result.heisenbug_confirmed_externally) {
            logS3(`     !!!! HEISENBUG CONFIRMADA EXTERNAMENTE !!!! 'this' type na última sonda capturada: ${result.toJSON_details.this_type_in_toJSON}`, "vuln", FNAME_RUNNER);
            if (result.toJSON_details.this_was_victim_ref !== null) { // Nome da propriedade da v11
                logS3(`       Na sonda relevante, 'this' === victim_typed_array_ref_v11? ${result.toJSON_details.this_was_victim_ref}`, "info");
            }
            document.title = `Heisenbug (TypedArray-VGPDC) TC CONFIRMED`;
        } else {
            logS3(`     Heisenbug NÃO confirmada externamente. Último tipo de 'this' capturado: ${result.toJSON_details ? result.toJSON_details.this_type_in_toJSON : 'N/A'}`, "warn", FNAME_RUNNER);
             if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC) || document.title.includes("Probing")) {
                document.title = `Heisenbug (TypedArray-VGPDC) TC Not Confirmed`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (VerifyGlobalProbeDetailsCapture) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Verificando Captura de Detalhes da Sonda ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("CONFIRMED") && !document.title.includes("NOT Confirmed") && 
            !document.title.includes("ERR")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC} Concluído`;
        }
    }
}
