// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_InspectPromiseConfusedAB, // ATUALIZADO para v67
    FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB // ATUALIZADO para v67
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_InspectPromiseConfusedAB";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_InspectPromiseConfusedAB();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado para o runner.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain && result.errorCapturedMain.message && result.errorCapturedMain.message.includes("Failed to get Confused ArrayBuffer")) {
        // ... (tratamento de erro específico da v65/v66)
    } else if (result.errorCapturedMain) {
        // ... (tratamento de erro geral)
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const promiseConfusionHit = result.all_probe_calls_for_analysis.find(d => d.this_is_ConfusedAB && d.this_type === '[object Promise]' && d.inspection_info !== null);
            if (promiseConfusionHit) {
                 logS3(`  !!!! CONFUSED AB SE TORNOU 'this' COMO [object Promise] E FOI INSPECIONADO (Call #${promiseConfusionHit.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else {
                const normalDvFuzz = result.all_probe_calls_for_analysis.find(d => d.this_is_NormalDV && d.fuzz_capture_info !== null);
                if (normalDvFuzz){
                    logS3(`  NormalDV foi fuzzed como controle.`, "info", FNAME_RUNNER);
                    heisenbugConfirmed = true; // Pelo menos o fluxo para DV funcionou
                } else {
                     logS3(`  ALERT: Nenhuma indicação clara de Heisenbug esperado (Promise ou DV fuzzed).`, "error", FNAME_RUNNER);
                }
            }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) { // ConfusedAB / Promise
            logS3(`    ADDROF A (ConfusedAB/Promise): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) { // NormalDV
            logS3(`    ADDROF B (NormalDV): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        // ... (lógica de título do documento similar à v66)
        if (anyAddrofSuccess) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: Addr SUCCESS!`; }
        else if (heisenbugConfirmed) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: Heisenbug OK, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: No Heisenbug?`; }
    }
    // ... (resto da função similar à v66)
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v66, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB)
    // ... (incluindo a lógica final de ajuste do document.title)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (InspectPromiseConfusedAB) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK") &&
            !document.title.includes("ConfusedAB Gen FAIL") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB} Concluído`;
        }
    }
}
