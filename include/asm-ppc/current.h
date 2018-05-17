/*
 * BK Id: SCCS/s.current.h 1.7 06/05/01 21:45:21 paulus
 */
#ifdef __KERNEL__
#ifndef _PPC_CURRENT_H
#define _PPC_CURRENT_H

/*
 * We keep `current' in r2 for speed.
 */
register struct task_struct *current asm ("r2");

#endif /* !(_PPC_CURRENT_H) */
#endif /* __KERNEL__ */
