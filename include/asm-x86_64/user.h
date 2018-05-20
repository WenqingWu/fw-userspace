#ifndef _X86_64_USER_H
#define _X86_64_USER_H

#include "types.h"
#include "page.h"
#include "../linux/ptrace.h"
/* Core file format: The core file is written in such a way that gdb
   can understand it and provide useful information to the user.
   There are quite a number of obstacles to being able to view the
   contents of the floating point registers, and until these are
   solved you will not be able to view the contents of them.
   Actually, you can read in the core file and look at the contents of
   the user struct to find out what the floating point registers
   contain.

   The actual file contents are as follows:
   UPAGE: 1 page consisting of a user struct that tells gdb what is present
   in the file.  Directly after this is a copy of the task_struct, which
   is currently not used by gdb, but it may come in useful at some point.
   All of the registers are stored as part of the upage.  The upage should
   always be only one page.
   DATA: The data area is stored.  We use current->end_text to
   current->brk to pick up all of the user variables, plus any memory
   that may have been malloced.  No attempt is made to determine if a page
   is demand-zero or if a page is totally unused, we just cover the entire
   range.  All of the addresses are rounded in such a way that an integral
   number of pages is written.
   STACK: We need the stack information in order to get a meaningful
   backtrace.  We need to write the data from (esp) to
   current->start_stack, so we round each of these off in order to be able
   to write an integer number of pages.
   The minimum core file size is 3 pages, or 12288 bytes.  */

/*
 * Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 *
 * Provide support for the GDB 5.0+ PTRACE_{GET|SET}FPXREGS requests for
 * interacting with the FXSR-format floating point environment.  Floating
 * point data can be accessed in the regular format in the usual manner,
 * and both the standard and SIMD floating point data can be accessed via
 * the new ptrace requests.  In either case, changes to the FPU environment
 * will be reflected in the task's state as expected.
 * 
 * x86-64 support by Andi Kleen.
 */

/* This matches the 64bit FXSAVE format as defined by AMD. It is the same
   as the 32bit format defined by Intel, except that the selector:offset pairs for
   data and eip are replaced with flat 64bit pointers. */ 
struct user_i387_struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd; /* Note this is not the same as the 32bit/x87/FSAVE twd */
	unsigned short	fop;
	u64	rip;
	u64	rdp;
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32	padding[24];
};

/*
 * Segment register layout in coredumps.
 */
struct user_regs_struct {
	unsigned long r15,r14,r13,r12,rbp,rbx,r11,r10;
	unsigned long r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
	unsigned long rip,cs,eflags;
	unsigned long rsp,ss;
  	unsigned long fs_base, gs_base;
	unsigned long ds,es,fs,gs; 
}; 

/* When the kernel dumps core, it starts by dumping the user struct -
   this will be used by gdb to figure out where the data and stack segments
   are within the file, and what virtual addresses to use. */
struct user{
/* We start with the registers, to mimic the way that "memory" is returned
   from the ptrace(3,...) function.  */
  struct user_regs_struct regs;		/* Where the registers are actually stored */
/* ptrace does not yet supply these.  Someday.... */
  int u_fpvalid;		/* True if math co-processor being used. */
                                /* for this mess. Not yet used. */
  struct user_i387_struct i387;	/* Math Co-processor registers. */
/* The rest of this junk is to help gdb figure out what goes where */
  unsigned long int u_tsize;	/* Text segment size (pages). */
  unsigned long int u_dsize;	/* Data segment size (pages). */
  unsigned long int u_ssize;	/* Stack segment size (pages). */
  unsigned long start_code;     /* Starting virtual address of text. */
  unsigned long start_stack;	/* Starting virtual address of stack area.
				   This is actually the bottom of the stack,
				   the top of the stack is always found in the
				   esp register.  */
  long int signal;     		/* Signal that caused the core dump. */
  int reserved;			/* No longer used */
  struct user_pt_regs * u_ar0;	/* Used by gdb to help find the values for */
				/* the registers. */
  struct user_i387_struct* u_fpstate;	/* Math Co-processor pointer. */
  unsigned long magic;		/* To uniquely identify a core file */
  char u_comm[32];		/* User command that was responsible */
  unsigned long u_debugreg[8];
};
#define NBPG PAGE_SIZE
#define UPAGES 1
#define HOST_TEXT_START_ADDR (u.start_code)
#define HOST_STACK_END_ADDR (u.start_stack + u.u_ssize * NBPG)

#endif /* _X86_64_USER_H */
