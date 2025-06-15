// js/utils.mjs (VERSÃO SIMPLIFICADA E SINCRONIZADA PARA 32 BITS)

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export async function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Converte um número para uma string hexadecimal formatada.
 * Otimizado para números de 32 bits.
 * @param {number} val O número a ser convertido.
 * @param {number} bits O número de bits para a formatação (default: 32).
 * @returns {string} A string hexadecimal formatada.
 */
export function toHex(val, bits = 32) {
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`;
    }
    if (isNaN(val)) {
        return 'ValIsNaN';
    }

    const numChars = Math.ceil(bits / 4);
    if (val < 0) {
        // Usa o operador de deslocamento de bits para obter a representação de complemento de dois
        return '0x' + (val >>> 0).toString(16).padStart(numChars, '0');
    }
    return '0x' + val.toString(16).padStart(numChars, '0');
}
