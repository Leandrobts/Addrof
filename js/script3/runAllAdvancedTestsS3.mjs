// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_StableC1_ReadOriginalBufferOfPromise, // ATUALIZADO para v70
    FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP // ATUALIZADO para v70
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_StableC1_ReadOriginalBufferOfPromise";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_StableC1_ReadOriginalBufferOfPromise();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio para o runner.`, "warn", FNAME_RUNNER);
    }

    // ... (lógica de tratamento de erro e de resultado similar à v69, adaptada para v70)
    // ...
    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        let titleSet = false;
        if (result.errorCapturedMain.message.includes("circular structure")){
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: CircularERR, Addr:${result.addrof_A_result?.success?'OK':'Fail'}`; // Adicionado ? para segurança
            titleSet = true;
        } else {
            document.title = `Heisenbug (TypedArray-SCROBOP) ERR: ${result.errorCapturedMain.name}`;
            titleSet = true;
        }
         if (!titleSet && result.addrof_A_result && result.addrof_A_result.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: ERR BUT Addr SUCCESS!`;
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);
        let heisenbugConfirmed = false;
        if (result.all_probe_calls_for_analysis) {
            const call2HitC1 = result.all_probe_calls_for_analysis.find(d => d.call_number === 2 && d.this_is_C1 && d.attempted_f64_leak_val !== null);
            if (call2HitC1) {
                 logS3(`  !!!! HEISENBUG NO C1_DETAILS (Call #2) & TENTATIVA DE LEAK f64 CONFIRMADAS!!!!`, "critical", FNAME_RUNNER);
                 heisenbugConfirmed = true;
            } else { logS3(`  ALERT: Heisenbug no C1 (Call #2) não confirmado.`, "error", FNAME_RUNNER); }
        }
        if (result.addrof_A_result) {
            logS3(`    ADDROF A (ConfusedObj/Promise): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_A_result.success) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: Addr SUCCESS!`; }
        else if (heisenbugConfirmed) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: Heisenbug OK, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: No Heisenbug?`; }
    }
    // ... (resto da função similar à v69)
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}_MainOrchestrator`;
    // ... (resto da função runAllAdvancedTestsS3 idêntica à v69, apenas com FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP)
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (StableC1_ReadOriginalBufferOfPromise) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
            !document.title.includes("ERR") &&
            !document.title.includes("Heisenbug OK") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP} Concluído`;
        }
    }
}
