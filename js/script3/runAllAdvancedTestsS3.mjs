// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 55 - Chamador do Bypass)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { AdvancedInt64 } from '../utils.mjs';

// CORREÇÃO: Importando os nomes corretos do nosso novo script de exploit.
import {
    FNAME_MODULE, // Nome correto da variável exportada
    runExploitChain_R55 // Nova função principal do exploit
} from './UltimateExploit.mjs'; //

// A função de teste do JIT permanece a mesma, pois é um bom sanity check.
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new AdvancedInt64(low, high);
    
    logS3(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN.", 'warn', 'testJITBehavior');
    }
    logS3("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}

// CORREÇÃO: A função do runner foi atualizada para chamar a nova lógica do R55.
async function runUltimateExploitStrategy() {
    const FNAME_RUNNER = "runUltimateExploitStrategy (R55)"; 
    logS3(`==== INICIANDO ESTRATÉGIA FINAL (${FNAME_MODULE}) ====`, 'test', FNAME_RUNNER);
    
    // Chama a nova função principal do exploit
    const result = await runExploitChain_R55();

    if (result.success) {
        logS3(`  RUNNER R55: CADEIA DE EXPLORAÇÃO BEM-SUCEDIDA!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R55: Mensagem: ${result.message}`, "good", FNAME_RUNNER);
        if (result.webkit_base) {
            logS3(`  RUNNER R55: Base do WebKit vazada: ${result.webkit_base.toString(true)}`, "leak", FNAME_RUNNER);
        }
        document.title = "PWNED by " + FNAME_MODULE; // Título da vitória
    } else {
        logS3(`  RUNNER R55: A cadeia de exploração falhou: ${result.errorOccurred}`, "critical", FNAME_RUNNER);
        document.title = FNAME_MODULE + ": FAIL";
    }

    logS3(`==== ESTRATÉGIA FINAL (${FNAME_MODULE}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`; // Usa o nome importado
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;

    await testJITBehavior();
    await PAUSE_S3(500);
    
    await runUltimateExploitStrategy(); // Chama a nova função runner

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
