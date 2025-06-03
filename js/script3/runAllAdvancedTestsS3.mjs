// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_DirectFuzzOnCoreConfusedABVictim, // ATUALIZADO para v69
    FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV // ATUALIZADO para v69
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_DirectFuzzOnCoreConfusedABVictim";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_DirectFuzzOnCoreConfusedABVictim();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) { /* ... (tratamento de erro similar ao v68) ... */ }
    else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const confusedABHit = result.all_probe_calls_for_analysis.find(d => d.this_is_confused_ab_target && (d.info || d.error_in_probe));
            if (confusedABHit) {
                 logS3(`  !!!! CONFUSED AB FOI 'this' E PROCESSADO PELA SONDA (Call #${confusedABHit.call_number}, Info: ${confusedABHit.info}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else { /* ... (fallback para NormalDV fuzzed) ... */ }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);
        // ... (logs de addrof A e B) ...
        // ... (lógica de título do documento) ...
        if (anyAddrofSuccess) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: Addr SUCCESS!`; }
        else if (heisenbugConfirmed) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: Heisenbug OK, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: No Heisenbug?`; }
    }
    // ... (resto da função similar à v68)
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v68, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV)
    // ... (incluindo a lógica final de ajuste do document.title)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (DirectFuzzOnCoreConfusedABVictim) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK") &&
            !document.title.includes("ConfusedAB Gen FAIL") ) { // Adicionar nova condição de falha
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV} Concluído`;
        }
    }
}
