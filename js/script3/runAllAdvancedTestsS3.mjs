// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 49 - Diagnóstico de DataView)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeDataViewScan_R49,
    FNAME_MODULE_DATAVIEW_SCANNER_R49
} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia de diagnóstico R49
async function runDataViewScanner_R49() {
    const FNAME_RUNNER = "runDataViewScanner_R49";
    logS3(`==== INICIANDO Estratégia de Diagnóstico de DataView (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeDataViewScan_R49();
    const module_name_for_title = FNAME_MODULE_DATAVIEW_SCANNER_R49;

    if (!result) {
        logS3(`  RUNNER R49: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }
    
    logS3(`  RUNNER R49: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: DataView Found!`;
        logS3(`  RUNNER R49: O OFFSET CORRETO É: 0x${result.dataview_offset.toString(16)}`, "vuln_major");
        logS3(`  RUNNER R49: Próximo passo: Atualize a constante 'OOB_DV_METADATA_BASE_IN_OOB_BUFFER' em core_exploit.mjs para este valor e execute a estratégia R48 novamente.`, "info_major");
    } else {
        document.title = `${module_name_for_title}: DataView NOT Found.`;
        logS3(`  RUNNER R49: O objeto DataView não está sendo alocado dentro do ArrayBuffer. A premissa do exploit é inválida para este ambiente e uma nova abordagem será necessária.`, "critical");
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_DATAVIEW_SCANNER_R49}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R49 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runDataViewScanner_R49();
    
    logS3(`\n==== Script 3 R49 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
}
