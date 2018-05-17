/*
 * BK Id: SCCS/s.div64.h 1.7 06/05/01 21:45:21 paulus
 */
#ifndef __PPC_DIV64
#define __PPC_DIV64

#define do_div(n,base) ({ \
int __res; \
__res = ((unsigned long) n) % (unsigned) base; \
n = ((unsigned long) n) / (unsigned) base; \
__res; })

#endif
