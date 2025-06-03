// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_LeakFromCoreConfusedAB, // ATUALIZADO para v65
    FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB // ATUALIZADO para v65
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_LeakFromCoreConfusedAB";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_LeakFromCoreConfusedAB();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado para o runner.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain && result.errorCapturedMain.message.includes("Failed to get Confused ArrayBuffer")) {
        logS3(`  TESTE ABORTADO: ${result.errorCapturedMain.message}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: ConfusedAB Gen FAIL`;
    } else if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-LFCAB) ERR: ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const fuzzCaptured = result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_ConfusedAB || d.this_is_leak_target_NormalDV) && d.fuzz_capture_status !== null);
            if (fuzzCaptured) {
                 logS3(`  !!!! ALVO DE LEAK (${fuzzCaptured.this_type}) TEVE FUZZING CAPTURADO (Call #${fuzzCaptured.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else { /* ... (lógica de fallback para heisenbugIndication) ... */ }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A (ConfusedAB): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B (NormalDV): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v64, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB)
    // ... (incluindo a lógica final de ajuste do document.title)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (LeakFromCoreConfusedAB) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK") &&
            !document.title.includes("ConfusedAB Gen FAIL") ) { // Adicionar nova condição de falha
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB} Concluído`;
        }
    }
}
