// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AnalyzeCoreExploitConfusedABMemory, // ATUALIZADO para v74
    FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM // ATUALIZADO para v74
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AnalyzeCoreExploitConfusedABMemory";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AnalyzeCoreExploitConfusedABMemory();

    logS3(`  Total de chamadas da sonda (dummy): ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda (dummy): ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda (dummy) foi retornado ou o array estava vazio.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ACECABM) ERR: ${result.errorCapturedMain.name}`;
    } else {
        // Para v74, o resultado principal está em addrof_A_result
        let heisenbugConfirmed = result.addrof_A_result && result.addrof_A_result.msg !== "Addrof CorruptedAB: Default (v74)";

        if (result.addrof_A_result) {
            logS3(`    ADDROF CorruptedAB: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (result.addrof_A_result && result.addrof_A_result.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed || result.addrof_A_result?.msg?.includes("verificado")) { // Se a corrupção foi verificada
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Corruption OK, Addr Fail`;
        } else if (result.addrof_A_result?.msg?.includes("FALHA CRÍTICA")) {
             document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Critical Fail (AddrOf AB)`;
        }
         else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Test Flow Issue or Addr Fail`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (AnalyzeCoreExploitConfusedABMemory) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Issue") &&
            !document.title.includes("Corruption OK") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM} Concluído`;
        }
    }
}
