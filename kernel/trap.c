#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

void 
store(void){
  struct proc *p = myproc();
  p->tick_ra = p->trapframe->ra;
  p->tick_sp = p->trapframe->sp;
  p->tick_gp = p->trapframe->gp;
  p->tick_tp = p->trapframe->tp;
  p->tick_t0 = p->trapframe->t0;
  p->tick_t1 = p->trapframe->t1;
  p->tick_t2 = p->trapframe->t2;
  p->tick_s0 = p->trapframe->s0;
  p->tick_s1 = p->trapframe->s1;
  p->tick_a0 = p->trapframe->a0;
  p->tick_a1 = p->trapframe->a1;
  p->tick_a2 = p->trapframe->a2;
  p->tick_a3 = p->trapframe->a3;
  p->tick_a4 = p->trapframe->a4;
  p->tick_a5 = p->trapframe->a5;
  p->tick_a6 = p->trapframe->a6;
  p->tick_a7 = p->trapframe->a7;
  p->tick_s2 = p->trapframe->s2;
  p->tick_s3 = p->trapframe->s3;
  p->tick_s4 = p->trapframe->s4;
  p->tick_s5 = p->trapframe->s5;
  p->tick_s6 = p->trapframe->s6;
  p->tick_s7 = p->trapframe->s7;
  p->tick_s8 = p->trapframe->s8;
  p->tick_s9 = p->trapframe->s9;
  p->tick_s10 = p->trapframe->s10;
  p->tick_s11 = p->trapframe->s11;
  p->tick_t3 = p->trapframe->t3;
  p->tick_t4 = p->trapframe->t4;
  p->tick_t5 = p->trapframe->t5;
  p->tick_t6 = p->trapframe->t6;
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();
  } else if((which_dev = devintr()) != 0){
    //ok
    /*if(which_dev ==2 && p->waitReturn==0){
      if(p->interval !=0){
        p->spend = p->spend + 1;
        if(p->spend == p->interval){
          switchTrapframe(p->trapframeSave,p->trapframe);
          p->spend = 0;
          p->trapframe->epc = (uint64)p->handler;
          p->waitReturn = 1;
        }
      }
    }*/

  } else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2){
    if(p->ticks>0){
      p->ticks_cnt++;
      if(p->handler_executing == 0 && p->ticks_cnt > p->ticks){
        p->ticks_cnt=0;

        p->tick_epc = p->trapframe->epc;
        store();
        p->handler_executing=1;
        p->trapframe->epc=p->handler;
      }
    }
    yield();

  }

  usertrapret();
}

//
// return to user space
//
void
usertrapret(void)
{
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(), so turn off interrupts until
  // we're back in user space, where usertrap() is correct.
  intr_off();

  // send syscalls, interrupts, and exceptions to trampoline.S
  w_stvec(TRAMPOLINE + (uservec - trampoline));

  // set up trapframe values that uservec will need when
  // the process next re-enters the kernel.
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->trapframe->epc);

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);

  // jump to trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 fn = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64,uint64))fn)(TRAPFRAME, satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause %p\n", scause);
    printf("sepc=%p stval=%p\n", r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  acquire(&tickslock);
  ticks++;
  wakeup(&ticks);
  release(&tickslock);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if((scause & 0x8000000000000000L) &&
     (scause & 0xff) == 9){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000001L){
    // software interrupt from a machine-mode timer interrupt,
    // forwarded by timervec in kernelvec.S.

    if(cpuid() == 0){
      clockintr();
    }
    
    // acknowledge the software interrupt by clearing
    // the SSIP bit in sip.
    w_sip(r_sip() & ~2);

    return 2;
  } else {
    return 0;
  }
}

/*void switchTrapframe(struct trapframe* trapframe, struct trapframe *trapframeSave){
  trapframe->kernel_satp = trapframeSave->kernel_satp;
  trapframe->kernel_sp = trapframeSave->kernel_sp;
  trapframe->epc = trapframeSave->epc;
  trapframe->kernel_hartid = trapframeSave->kernel_hartid;
  trapframe->ra = trapframeSave->ra;
  trapframe->sp = trapframeSave->sp;
  trapframe->gp = trapframeSave->gp;
  trapframe->tp = trapframeSave->tp;
  trapframe->t0 = trapframeSave->t0;
  trapframe->t1 = trapframeSave->t1;
  trapframe->t2 = trapframeSave->t2;
  trapframe->s0 = trapframeSave->s0;
  trapframe->s1 = trapframeSave->s1;
  trapframe->a0 = trapframeSave->a0;
  trapframe->a1 = trapframeSave->a1;
  trapframe->a2 = trapframeSave->a2;
  trapframe->a3 = trapframeSave->a3;
  trapframe->a4 = trapframeSave->a4;
  trapframe->a5 = trapframeSave->a5;
  trapframe->a6 = trapframeSave->a6;
  trapframe->a7 = trapframeSave->a7;
  trapframe->s2 = trapframeSave->s2;
  trapframe->s3 = trapframeSave->s3;
  trapframe->s4 = trapframeSave->s4;
  trapframe->s5 = trapframeSave->s5;
  trapframe->s6 = trapframeSave->s6;
  trapframe->s7 = trapframeSave->s7;
  trapframe->s8 = trapframeSave->s8;
  trapframe->s9 = trapframeSave->s9;
  trapframe->s10 = trapframeSave->s10;
  trapframe->s11 = trapframeSave->s11;
  trapframe->t3 = trapframeSave->t3;
  trapframe->t4 = trapframeSave->t4;
  trapframe->t5 = trapframeSave->t5;
  trapframe->t6 = trapframeSave->t6;
}
*/