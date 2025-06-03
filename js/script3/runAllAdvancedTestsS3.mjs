// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_VerifyConfigConstants, // ATUALIZADO para v75
    FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC // ATUALIZADO para v75
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_VerifyConfigConstants";
    logS3(`==== INICIANDO Estratégia de Teste (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_VerifyConfigConstants();

    logS3(`  Total de chamadas da sonda (se houver): ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio.`, "info", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO DO TESTE DE CONFIG: ERRO - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: Config Test ERR`;
    } else if (result.stringifyResult && result.stringifyResult.success) {
        logS3(`  RESULTADO DO TESTE DE CONFIG: SUCESSO - ${result.stringifyResult.message}`, "good", FNAME_RUNNER);
        logS3(`    Struct ID Str: '${result.stringifyResult.struct_id_str_val}' (Type: ${result.stringifyResult.struct_id_str_type}) -> Adv64: ${result.stringifyResult.adv64_struct_id}`, "good", FNAME_RUNNER);
        logS3(`    Butterfly Str: '${result.stringifyResult.butterfly_str_val}' (Type: ${result.stringifyResult.butterfly_str_type}) -> Adv64: ${result.stringifyResult.adv64_butterfly}`, "good", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: Config OK`;
    } else if (result.stringifyResult) { // Se stringifyResult existe, mas success é false
        logS3(`  RESULTADO DO TESTE DE CONFIG: FALHA - ${result.stringifyResult.message}`, "error", FNAME_RUNNER);
        logS3(`    Struct ID Str: '${result.stringifyResult.struct_id_str_val}' (Type: ${result.stringifyResult.struct_id_str_type})`, "error", FNAME_RUNNER);
        logS3(`    Butterfly Str: '${result.stringifyResult.butterfly_str_val}' (Type: ${result.stringifyResult.butterfly_str_type})`, "error", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: Config FAIL`;
    } else {
        logS3(`  RESULTADO DO TESTE DE CONFIG: Estrutura de resultado inesperada.`, "error", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: Result ERR`;
    }

    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Teste (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Verificando Constantes de Config (v75) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC)) {
        if (!document.title.includes("FAIL") && !document.title.includes("ERR") && !document.title.includes("OK") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC} Verificação Concluída`;
        }
    }
}
