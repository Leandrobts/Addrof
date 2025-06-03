// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_InspectPromiseRobustly, // ATUALIZADO para v68
    FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR // ATUALIZADO para v68
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_InspectPromiseRobustly";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_InspectPromiseRobustly();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    // AGORA `result.all_probe_calls_for_analysis` deve ser um array, mesmo que vazio.
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio.`, "warn", FNAME_RUNNER);
    }

    // ... (lógica de tratamento de erro e de resultado similar à v66, adaptada para v68)
    if (result.errorCapturedMain && result.errorCapturedMain.message && result.errorCapturedMain.message.includes("Failed to get Confused ArrayBuffer")) {
        logS3(`  TESTE ABORTADO: ${result.errorCapturedMain.message}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: ConfusedAB Gen FAIL`;
    } else if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-IPR) ERR: ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const promiseInspected = result.all_probe_calls_for_analysis.find(d => d.this_is_ConfusedAB && d.this_type === '[object Promise]' && d.inspection_capture_info !== null);
            if (promiseInspected) {
                 logS3(`  !!!! CONFUSED AB (como Promise) FOI 'this' E INSPECIONADO (Call #${promiseInspected.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else { /* ... (fallback para NormalDV fuzzed ou C1 populado) ... */ }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);
        // ... (logs de addrof A e B) ...
        // ... (lógica de título do documento) ...
        if (anyAddrofSuccess) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: Addr SUCCESS!`; }
        else if (heisenbugConfirmed) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: Heisenbug OK, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: No Heisenbug?`; }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v66, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR)
    // ... (incluindo a lógica final de ajuste do document.title)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (InspectPromiseRobustly) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK") &&
            !document.title.includes("ConfusedAB Gen FAIL") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR} Concluído`;
        }
    }
}
