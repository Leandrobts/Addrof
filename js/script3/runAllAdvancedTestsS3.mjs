// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 46 - Escaneador de Heap)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    // NOVO: Importa a nova função de diagnóstico R46.
    executeHeapScan_R46,
    FNAME_MODULE_HEAP_SCANNER_R46
} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia de diagnóstico R46
async function runHeapScannerStrategy_R46() {
    const FNAME_RUNNER = "runHeapScannerStrategy_R46";
    logS3(`==== INICIANDO Estratégia de Escaneamento de Heap (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeHeapScan_R46();
    const module_name_for_title = FNAME_MODULE_HEAP_SCANNER_R46;

    if (!result) {
        logS3(`  RUNNER R46: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }
    
    logS3(`  RUNNER R46: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: Scan Found Objects!`;
        logS3(`  RUNNER R46: OBJETOS ENCONTRADOS:`, "vuln");
        console.log(result.found_objects); // Loga o objeto no console para fácil visualização
    } else {
        document.title = `${module_name_for_title}: Scan Found Nothing.`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_HEAP_SCANNER_R46}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R46 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeapScannerStrategy_R46();
    
    logS3(`\n==== Script 3 R46 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
}
