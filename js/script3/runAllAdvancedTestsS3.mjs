// js/script3/runAllAdvancedTestsS3.mjs (CORRIGIDO v2)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// --- CORREÇÃO: A importação abaixo causa um SyntaxError porque a função não é exportada pelo módulo de destino. ---
// import {
//     executeTypedArrayVictimAddrofAndWebKitLeak_R43
// } from './testArrayBufferVictimCrash.mjs';
import { testJsonTypeConfusionUAFSpeculative } from './testJsonTypeConfusionUAFSpeculative.mjs';

const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = 'testTypedArrayAddrof_v82_AGL_R43_WebKit';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43";
    logS3(`==== AVISO: Pulando suíte de testes (${FNAME_RUNNER}) devido a um erro de importação. ====`, 'warn', FNAME_RUNNER);
    logS3(`  A função 'executeTypedArrayVictimAddrofAndWebKitLeak_R43' não foi encontrada em './testArrayBufferVictimCrash.mjs'.`, 'error', FNAME_RUNNER);

    // --- CORREÇÃO: A chamada da função foi comentada para prevenir o SyntaxError. ---
    // const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    // Um objeto de erro é simulado para permitir que o script continue sem travar.
    const result = { errorOccurred: "Erro de importação: a função de teste não foi encontrada." };

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(L): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Import ERROR!`; // Título reflete o erro de importação
    } else if (result) {
        // Este bloco de código não será executado devido ao erro simulado, o que é o comportamento esperado.
        logS3(`  RUNNER R43(L): Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        // ... (o resto do tratamento de sucesso é ignorado com segurança)
    } else {
        document.title = `${module_name_for_title}_R43L: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA (com falha de importação) ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R43L (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);

    // --- Executa a primeira suíte de testes (Heisenbug) ---
    // Esta função agora lidará com a falha de importação internamente e não irá travar.
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();

    // --- Executa a segunda suíte de testes (JSON UAF/TC Especulativo) ---
    // Esta parte do código será executada normalmente.
    logS3(`\n==== ORQUESTRADOR: Pausando antes de iniciar a próxima suíte de testes... ====`, 'test', FNAME_ORCHESTRATOR);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    await testJsonTypeConfusionUAFSpeculative();

    // --- Finalização ---
    logS3(`\n==== Script 3 R43L (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    // Lógica de título final ajustada
    if (document.title.includes("Import ERROR!")) {
        // Título já reflete o erro, não fazer nada.
    } else if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") && !document.title.includes("Confirmed")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43L Done`;
    }
}
