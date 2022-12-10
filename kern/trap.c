#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

extern uintptr_t gdtdesc_64;
struct Taskstate ts;
extern struct Segdesc gdt[];
extern long gdt_pd;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {0,0};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
    // jchung: first declare functions as extern void, and then use SETGATE
    extern void XTRAPX_DIVIDE();
    extern void XTRAPX_DEBUG();
    extern void XTRAPX_NMI();
    extern void XTRAPX_BRKPT();
    extern void XTRAPX_OFLOW();
    extern void XTRAPX_BOUND();
    extern void XTRAPX_ILLOP();
    extern void XTRAPX_DEVICE();
    extern void XTRAPX_DBLFLT();
    //extern void XTRAPX_COPROC();
    extern void XTRAPX_TSS();
    extern void XTRAPX_SEGNP();
    extern void XTRAPX_STACK();
    extern void XTRAPX_GPFLT();
    extern void XTRAPX_PGFLT();
    //extern void XTRAPX_RES();
    extern void XTRAPX_FPERR();
    extern void XTRAPX_ALIGN();
    extern void XTRAPX_MCHK();
    extern void XTRAPX_SIMDERR();
    extern void XTRAPX_SYSCALL();
    extern void XTRAPX_DEFAULT();

    // Lab 4 - jchung
    extern void XTRAPX_IRQ00();
    extern void XTRAPX_IRQ01();
    extern void XTRAPX_IRQ02();
    extern void XTRAPX_IRQ03();
    extern void XTRAPX_IRQ04();
    extern void XTRAPX_IRQ05();
    extern void XTRAPX_IRQ06();
    extern void XTRAPX_IRQ07();
    extern void XTRAPX_IRQ08();
    extern void XTRAPX_IRQ09();
    extern void XTRAPX_IRQ10();
    extern void XTRAPX_IRQ11();
    extern void XTRAPX_IRQ12();
    extern void XTRAPX_IRQ13();
    extern void XTRAPX_IRQ14();
    extern void XTRAPX_IRQ15();

    SETGATE(idt[T_DIVIDE], 0, GD_KT, XTRAPX_DIVIDE, 0);
    SETGATE(idt[T_DEBUG], 0, GD_KT, XTRAPX_DEBUG, 0);
    SETGATE(idt[T_NMI], 0, GD_KT, XTRAPX_NMI, 0);
    // jchung: from L3E5
    // 'general protection fault depending on how you initialized the break point entry in the IDT'
    // set DPL to 3 and not 0 for it to cause breakpoint exception and not general protection fault
    SETGATE(idt[T_BRKPT], 0, GD_KT, XTRAPX_BRKPT, 3);
    SETGATE(idt[T_OFLOW], 0, GD_KT, XTRAPX_OFLOW, 0);
    SETGATE(idt[T_BOUND], 0, GD_KT, XTRAPX_BOUND, 0);
    SETGATE(idt[T_ILLOP], 0, GD_KT, XTRAPX_ILLOP, 0);
    SETGATE(idt[T_DEVICE], 0, GD_KT, XTRAPX_DEVICE, 0);
    SETGATE(idt[T_DBLFLT], 0, GD_KT, XTRAPX_DBLFLT, 0);
    //SETGATE(idt[T_COPROC], 0, GD_KT, XTRAPX_COPROC, 0);
    SETGATE(idt[T_TSS], 0, GD_KT, XTRAPX_TSS, 0);
    SETGATE(idt[T_SEGNP], 0, GD_KT, XTRAPX_SEGNP, 0);
    SETGATE(idt[T_STACK], 0, GD_KT, XTRAPX_STACK, 0);
    SETGATE(idt[T_GPFLT], 0, GD_KT, XTRAPX_GPFLT, 0);
    SETGATE(idt[T_PGFLT], 0, GD_KT, XTRAPX_PGFLT, 0);
    //SETGATE(idt[T_RES], 0, GD_KT, XTRAPX_RES, 0);
    SETGATE(idt[T_FPERR], 0, GD_KT, XTRAPX_FPERR, 0);
    SETGATE(idt[T_ALIGN], 0, GD_KT, XTRAPX_ALIGN, 0);
    SETGATE(idt[T_MCHK], 0, GD_KT, XTRAPX_MCHK, 0);
    SETGATE(idt[T_SIMDERR], 0, GD_KT, XTRAPX_SIMDERR, 0);
    SETGATE(idt[T_SYSCALL], 0, GD_KT, XTRAPX_SYSCALL, 3);
    SETGATE(idt[T_DEFAULT], 0, GD_KT, XTRAPX_DEFAULT, 0);

    // Lab 4 - jchung
	SETGATE(idt[IRQ_OFFSET + 0], 0, GD_KT, XTRAPX_IRQ00, 0);
	SETGATE(idt[IRQ_OFFSET + 1], 0, GD_KT, XTRAPX_IRQ01, 0);
	SETGATE(idt[IRQ_OFFSET + 2], 0, GD_KT, XTRAPX_IRQ02, 0);
	SETGATE(idt[IRQ_OFFSET + 3], 0, GD_KT, XTRAPX_IRQ03, 0);
	SETGATE(idt[IRQ_OFFSET + 4], 0, GD_KT, XTRAPX_IRQ04, 0);
	SETGATE(idt[IRQ_OFFSET + 5], 0, GD_KT, XTRAPX_IRQ05, 0);
	SETGATE(idt[IRQ_OFFSET + 6], 0, GD_KT, XTRAPX_IRQ06, 0);
	SETGATE(idt[IRQ_OFFSET + 7], 0, GD_KT, XTRAPX_IRQ07, 0);
	SETGATE(idt[IRQ_OFFSET + 8], 0, GD_KT, XTRAPX_IRQ08, 0);
	SETGATE(idt[IRQ_OFFSET + 9], 0, GD_KT, XTRAPX_IRQ09, 0);
	SETGATE(idt[IRQ_OFFSET + 10], 0, GD_KT, XTRAPX_IRQ10, 0);
	SETGATE(idt[IRQ_OFFSET + 11], 0, GD_KT, XTRAPX_IRQ11, 0);
	SETGATE(idt[IRQ_OFFSET + 12], 0, GD_KT, XTRAPX_IRQ12, 0);
	SETGATE(idt[IRQ_OFFSET + 13], 0, GD_KT, XTRAPX_IRQ13, 0);
	SETGATE(idt[IRQ_OFFSET + 14], 0, GD_KT, XTRAPX_IRQ14, 0);
	SETGATE(idt[IRQ_OFFSET + 15], 0, GD_KT, XTRAPX_IRQ15, 0);
    
    idt_pd.pd_lim = sizeof(idt)-1;
	idt_pd.pd_base = (uint64_t)idt;
	// Per-CPU setup
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + 2*i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
    
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
    // the ID of the current CPU is given by cpunum() or thiscpu->cpu_id
    thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - thiscpu->cpu_id * (KSTKSIZE + KSTKGAP);

	// Initialize the TSS slot of the gdt.
    // use gdt[(GD_TSS0 >> 3) + 2 * i] for CPU i's TSS descriptor
    SETTSS((struct SystemSegdesc64 *)(&gdt[(GD_TSS0 >> 3) + 2 * thiscpu->cpu_id]),
           STS_T64A,
           (uint64_t)(&(thiscpu->cpu_ts)),
           sizeof(struct Taskstate),
           0);
	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
    ltr(((GD_TSS0 >> 3) + 2 * thiscpu->cpu_id) << 3);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  rip  0x%08x\n", tf->tf_rip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  rsp  0x%08x\n", tf->tf_rsp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  r15  0x%08x\n", regs->reg_r15);
	cprintf("  r14  0x%08x\n", regs->reg_r14);
	cprintf("  r13  0x%08x\n", regs->reg_r13);
	cprintf("  r12  0x%08x\n", regs->reg_r12);
	cprintf("  r11  0x%08x\n", regs->reg_r11);
	cprintf("  r10  0x%08x\n", regs->reg_r10);
	cprintf("  r9  0x%08x\n", regs->reg_r9);
	cprintf("  r8  0x%08x\n", regs->reg_r8);
	cprintf("  rdi  0x%08x\n", regs->reg_rdi);
	cprintf("  rsi  0x%08x\n", regs->reg_rsi);
	cprintf("  rbp  0x%08x\n", regs->reg_rbp);
	cprintf("  rbx  0x%08x\n", regs->reg_rbx);
	cprintf("  rdx  0x%08x\n", regs->reg_rdx);
	cprintf("  rcx  0x%08x\n", regs->reg_rcx);
	cprintf("  rax  0x%08x\n", regs->reg_rax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
    //print_trapframe(tf);
	// LAB 3: Your code here.
	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
    switch (tf->tf_trapno) {
    case T_PGFLT:
        page_fault_handler(tf);
        break;
    case T_BRKPT:
        monitor(tf);
        break;
    case T_SYSCALL:
        tf->tf_regs.reg_rax = syscall(tf->tf_regs.reg_rax,
                                      tf->tf_regs.reg_rdx,
                                      tf->tf_regs.reg_rcx,
                                      tf->tf_regs.reg_rbx,
                                      tf->tf_regs.reg_rdi,
                                      tf->tf_regs.reg_rsi);
        break;
    // Lab 4 Exercise 14
    case (IRQ_OFFSET + IRQ_SPURIOUS):
        panic("should not have reached here\n");
        break;
    case (IRQ_OFFSET + IRQ_TIMER):
        // acknowledge interrupt using lapic_eoi before calling scheduler
        lapic_eoi();
        sched_yield();
        break;
	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.
    case (IRQ_OFFSET + IRQ_KBD):
        kbd_intr();
        break;
    case (IRQ_OFFSET + IRQ_SERIAL):
        serial_intr();
        break;
    default:
        // Unexpected trap: The user process or the kernel has a bug.
	    print_trapframe(tf);
	    if (tf->tf_cs == GD_KT)
	        panic("unhandled trap in kernel");
	    else {
	        env_destroy(curenv);
	        return;
	    }
    }
}

void
trap(struct Trapframe *tf)
{
	//struct Trapframe *tf = &tf_;
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
        lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint64_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
    // jchung: CS is 0 in kernel mode and 3 in user mode
    if ((tf->tf_cs & 3) == 0)
        panic("page_fault_handler: page fault in kernel mode (CS == 0)\n");
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
    if (curenv->env_pgfault_upcall) {
        struct UTrapframe *userTf;
        // check if we were already on exception stack upon fault
        // already in user exception stack area --> push empty 8B word and then struct UTrapframe
        // not in user exception stack area     --> push struct UTrapframe
        if (((UXSTACKTOP - PGSIZE) <= curenv->env_tf.tf_rsp) && (curenv->env_tf.tf_rsp < UXSTACKTOP))
            userTf = (struct UTrapframe *)(curenv->env_tf.tf_rsp - sizeof(struct UTrapframe) - 8);
        else
            userTf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
        
        // use user_mem_assert to check if address is valid --> can we write to userTf as user?
        user_mem_assert(curenv, (const void *)userTf, sizeof(struct UTrapframe), PTE_P | PTE_U | PTE_W);
        // set registers
        userTf->utf_fault_va    = fault_va;
        userTf->utf_err         = curenv->env_tf.tf_err;
        userTf->utf_regs        = curenv->env_tf.tf_regs;
        userTf->utf_rip         = curenv->env_tf.tf_rip;
        userTf->utf_eflags      = curenv->env_tf.tf_eflags;
        userTf->utf_rsp         = curenv->env_tf.tf_rsp;

        // return back to designated pagefault handler
        curenv->env_tf.tf_rip = (uintptr_t)(curenv->env_pgfault_upcall);
        curenv->env_tf.tf_rsp = (uintptr_t)userTf;

        // return to execution?
        env_run(curenv);
    } else {
	    // Destroy the environment that caused the fault.
        // IF THERE IS NO PAGE FAULT HANDLER REGISTERED
	    cprintf("[%08x] user fault va %08x ip %08x\n", curenv->env_id, fault_va, tf->tf_rip);
	    print_trapframe(tf);
	    env_destroy(curenv);
    }
}

