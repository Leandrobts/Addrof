// js/script3/runAllAdvancedTestsS3.mjs (Runner para R62 - All-In com Corrupção de Length)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R62 as executeTest,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runStrategy_AllIn_R62() {
    const FNAME_RUNNER = "runStrategy_AllIn_R62";
    logS3(`==== INICIANDO Estratégia (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTest();
    const module_name_for_title = FNAME_MODULE;

    if (!result) {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R62(AllIn): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
        return;
    }

    if (result.webkit_leak_result?.success) {
        logS3(`  --- SUCESSO FINAL! ---`, "success_major", FNAME_RUNNER);
        logS3(`    Corrupção de Length: ${result.length_corruption_result?.success ? 'SUCESSO' : 'FALHA'}`, "good", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: ${result.addrof_result?.success ? 'CRIADA' : 'FALHOU'}`, "good", FNAME_RUNNER);
        logS3(`    Endereço Base do WebKit Vazado: ${result.webkit_leak_result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        document.title = "Exploit Sucesso: Base do WebKit Vazada!";
    } else if (result.addrof_result?.success) {
        logS3(`  --- SUCESSO PARCIAL (ADDROF OK) ---`, "vuln", FNAME_RUNNER);
        logS3(`    Corrupção de Length: ${result.length_corruption_result?.success ? 'SUCESSO' : 'FALHA'}`, "good", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: CRIADA COM SUCESSO.`, "good", FNAME_RUNNER);
        document.title = "Exploit Parcial: Addrof OK";
    } else if (result.length_corruption_result?.success) {
        logS3(`  --- SUCESSO PARCIAL (CORRUPÇÃO DE LENGTH OK) ---`, "vuln_potential", FNAME_RUNNER);
        logS3(`    Notas: ${result.length_corruption_result.notes}`, "info", FNAME_RUNNER);
        document.title = "Exploit Parcial: Corrupção de Length OK";
    } else {
        logS3(`  --- FALHA NO TESTE ---`, "critical", FNAME_RUNNER);
        logS3(`    Erro reportado: ${result.errorOccurred || 'Erro desconhecido'}`, "error", FNAME_RUNNER);
        document.title = "Exploit Falhou: Verifique Logs";
    }
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R62_AllIn (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStrategy_AllIn_R62();
    
    logS3(`\n==== Script 3 R62_AllIn (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
