// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_ReadExplicitlyCorruptedFields,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF
} from './testArrayBufferVictimCrash.mjs'; // <- Este é o arquivo do teste principal (v72)

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    // ... conteúdo da função ...
}

// Esta é a exportação que o run_isolated_test.mjs está procurando
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF}_MainOrchestrator`;
    // ... resto da função ...
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ReadExplicitlyCorruptedFields) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
            !document.title.includes("ERR") &&
            !document.title.includes("Test Flow Issue") ) { // Adicionado da v72
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V72_RECF} Concluído`;
        }
    }
}
