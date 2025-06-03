// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_MultiInjectAndStabilize, // ATUALIZADO para v52
    FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS // ATUALIZADO para v52
} from './testArrayBufferVictimCrash.mjs'; // Assumindo que o arquivo v52 ainda se chama testArrayBufferVictimCrash.mjs

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    // ATUALIZADO para refletir v52
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_MultiInjectAndStabilize";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (MultiInjectAndStabilize) ====`, 'test', FNAME_RUNNER);

    // ATUALIZADO para chamar a função v52
    const result = await executeTypedArrayVictimAddrofTest_MultiInjectAndStabilize();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) { // O objeto de resultado da v52 usa errorCapturedMain
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        // ATUALIZADO para refletir v52 no título do documento
        document.title = `Heisenbug (TypedArray-MAS) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorCapturedMain.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é um SINAL MUITO BOM de controle profundo!`, "good", FNAME_RUNNER);
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        // A lógica para confirmar o heisenbug pode precisar de ajuste se a estrutura do 'relevantCall' mudou,
        // mas a v52 ainda popula 'payload_A_assigned' em 'all_probe_interaction_details_v52'
        const relevantCall = result.all_probe_calls_for_analysis.find(d => d.this_type === '[object Object]' && d.payload_A_assigned);
        if (relevantCall) {
            heisenbugConfirmed = true;
            logS3(`  !!!! HEISENBUG & PAYLOAD ASSIGNMENT CONFIRMADAS NA CHAMADA #${relevantCall.call_number} !!!! Tipo: ${relevantCall.this_type}`, "critical", FNAME_RUNNER);
        } else {
            logS3(`  ALERT: Heisenbug/Payload Assignment NÃO CONFIRMADA EM NENHUMA CHAMADA DE OBJETO.`, "error", FNAME_RUNNER);
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
            logS3(`    ADDROF A SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
            logS3(`    ADDROF A FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
            logS3(`    ADDROF B SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
            logS3(`    ADDROF B FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }

        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        // ATUALIZADO para refletir v52 no título do documento
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // ATUALIZADO para refletir v52
    logS3(`==== Estratégia de Reprodução do Heisenbug (MultiInjectAndStabilize) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // ATUALIZADO para refletir v52
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
    // ATUALIZADO para refletir v52
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (MultiInjectAndStabilize) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // ATUALIZADO para refletir v52 no título do documento
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V52_MAS} Concluído`;
        }
    }
}
