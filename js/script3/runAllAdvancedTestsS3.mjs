// js/script3/runAllAdvancedTestsS3.mjs (Runner para R62 - All-In com Corrupção de Length)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTest, // CORRIGIDO
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
    
    if (result.errorOccurred) {
        logS3(`  --- FALHA NO TESTE ---`, "critical", FNAME_RUNNER);
        logS3(`    Erro reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER);
        document.title = "Exploit Falhou: Verifique Logs";
    } else if (result.addrof_result?.success) {
        logS3(`  --- SUCESSO PARCIAL (PRIMITIVA R/W OBTIDA) ---`, "success_major", FNAME_RUNNER);
        logS3(`    Resultado: ${result.addrof_result.msg}`, "good", FNAME_RUNNER);
        logS3(`    Parâmetros OOB do Sucesso: Offset=${result.oob_params_of_best_result?.offset}, Valor=${result.oob_params_of_best_result?.value}`, "info", FNAME_RUNNER);
        logS3(`    Próximo passo: Usar a primitiva de R/W relativa para construir addrof/fakeobj.`, "info_emphasis", FNAME_RUNNER);
        document.title = "Sucesso: Primitiva de R/W Relativa Obtida!";
    } else if (result.heisenbug_on_M2_confirmed_by_tc_probe) {
        logS3(`  --- SEM SUCESSO DE EXPLOIT, MAS TC ESTÁVEL ---`, "vuln", FNAME_RUNNER);
        logS3(`    Confusão de Tipos foi confirmada, mas nenhuma corrupção útil foi encontrada.`, "warn", FNAME_RUNNER);
        document.title = "TC OK, mas sem R/W ou Addrof";
    } else {
        logS3(`  --- FALHA NO TESTE (SEM ERRO EXPLÍCITO) ---`, "critical", FNAME_RUNNER);
        document.title = "Exploit Falhou Inesperadamente";
    }

    if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
        logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
        result.iteration_results_summary.forEach((iter_sum, index) => {
            let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
            let highlights = [];
            if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
            if (iter_sum.addrof_success_this_iter) highlights.push("LENGTH_CORRUPT_OK");
            
            if (highlights.length > 0) { logMsg += highlights.join(", "); }
            else { logMsg += "Sem Efeitos Notáveis"; }
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            
            logS3(logMsg, iter_sum.addrof_success_this_iter ? "success_major" : "info", FNAME_RUNNER);
        });
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
