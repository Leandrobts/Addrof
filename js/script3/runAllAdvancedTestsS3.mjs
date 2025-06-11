// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO PARA TESTE DE LEAK)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa o NOVO teste de vazamento de memória
import { testMemoryLeakViaJsonTC } from './testMemoryLeakViaJsonTC.mjs'; 

// A constante do módulo antigo é mantida para o título da página e logs
const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = 'testTypedArrayAddrof_v82_AGL_R43_WebKit';

// A função antiga de teste de Heisenbug é desativada, pois o foco agora é o novo teste.
// Ela apenas registrará um aviso de que está sendo pulada.
async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43";
    logS3(`==== AVISO: Pulando suíte de testes legada (${FNAME_RUNNER}) para focar no novo exploit. ====`, 'warn', FNAME_RUNNER);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}: Legacy Skipped`;
    await PAUSE_S3(100); // Pausa curta
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `MainOrchestrator_LeakStrategy`;
    logS3(`==== INICIANDO ESTRATÉGIA DE EXPLORAÇÃO 1: VAZAMENTO DE MEMÓRIA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);

    // Desativa o botão de execução para evitar execuções múltiplas
    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    // --- Executa a suíte de testes de Heisenbug (agora desativada) para manter a estrutura ---
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();

    // --- Executa a NOVA suíte de testes focada no Vazamento de Memória ---
    logS3(`\n==== ORQUESTRADOR: Iniciando a tentativa de vazamento de endereço... ====`, 'test', FNAME_ORCHESTRATOR);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    
    // Ponto principal da nova estratégia
    await testMemoryLeakViaJsonTC();

    // --- Finalização ---
    logS3(`\n==== ESTRATÉGIA DE EXPLORAÇÃO 1 CONCLUÍDA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false; // Reativa o botão
    document.title = `LeakExploit: Done`;
}
