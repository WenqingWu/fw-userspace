/*
 * BK Id: SCCS/s.md.h 1.7 06/05/01 21:45:22 paulus
 */
/*
 * md.h: High speed xor_block operation for RAID4/5 
 *
 */
 
#ifdef __KERNEL__
#ifndef __ASM_MD_H
#define __ASM_MD_H

/* #define HAVE_ARCH_XORBLOCK */

#define MD_XORBLOCK_ALIGNMENT	sizeof(long)

#endif /* __ASM_MD_H */
#endif /* __KERNEL__ */
