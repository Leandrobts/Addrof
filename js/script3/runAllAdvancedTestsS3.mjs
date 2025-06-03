// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_FuzzCorruptedVictimItself, // ATUALIZADO para v71
    FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI // ATUALIZADO para v71
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FuzzCorruptedVictimItself";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FuzzCorruptedVictimItself();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio para o runner.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) { /* ... (tratamento de erro) ... */ }
    else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const victimFuzzed = result.all_probe_calls_for_analysis.find(d => d.call_number === 1 && d.this_is_victim && d.fuzz_capture_status !== null);
            if (victimFuzzed) {
                 logS3(`  !!!! VICTIM BUFFER FOI ALVO DE FUZZING NA CALL #1 !!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else {
                 logS3(`  ALERT: Victim buffer não parece ter sido fuzzed na Call #1.`, "error", FNAME_RUNNER);
            }
        }

        // Para v71, só temos addrof_A_result relevante
        if (result.addrof_A_result) {
            logS3(`    ADDROF VictimBuffer: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (result.addrof_A_result && result.addrof_A_result.success) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: Addr SUCCESS!`; }
        else if (heisenbugConfirmed) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: Heisenbug OK, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: No Heisenbug?`; }
    }
    // ... (resto da função similar à v69)
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v69, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI)
    // ... (incluindo a lógica final de ajuste do document.title)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (FuzzCorruptedVictimItself) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") &&
            !document.title.includes("Heisenbug OK") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI} Concluído`;
        }
    }
}
