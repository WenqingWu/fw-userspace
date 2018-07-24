/* kfree() */
#include	"../include/linux/config.h"
#include	"../include/linux/slab.h"
#include	"../include/linux/interrupt.h"
#include	"../include/linux/init.h"
#include	"../include/linux/compiler.h"
#include	"../include/linux/seq_file.h"
#include	"../include/asm/uaccess.h"

/* vfree()  */
#include "../include/linux/vmalloc.h"

/* do_softirq_thunk()  */
#include "../include/linux/mm.h"
#include "../include/linux/kernel_stat.h"
#include "../include/linux/smp_lock.h"
#include "../include/linux/tqueue.h"

/* ip_finish_output() */
#include "../include/asm/system.h"
#include "../include/linux/types.h"
#include "../include/linux/kernel.h"
#include "../include/linux/sched.h"
#include "../include/linux/string.h"
#include "../include/linux/errno.h"

#include "../include/linux/socket.h"
#include "../include/linux/sockios.h"
#include "../include/linux/in.h"
#include "../include/linux/inet.h"
#include "../include/linux/netdevice.h"
#include "../include/linux/etherdevice.h"
#include "../include/linux/proc_fs.h"
#include "../include/linux/stat.h"

#include "../include/net/snmp.h"
#include "../include/net/ip.h"
#include "../include/net/protocol.h"
#include "../include/net/route.h"
#include "../include/net/tcp.h"
#include "../include/net/udp.h"
#include "../include/linux/skbuff.h"
#include "../include/net/sock.h"
#include "../include/net/arp.h"
#include "../include/net/icmp.h"
#include "../include/net/raw.h"
#include "../include/net/checksum.h"
#include "../include/net/inetpeer.h"
#include "../include/linux/igmp.h"
#include "../include/linux/netfilter_ipv4.h"
#include "../include/linux/mroute.h"
#include "../include/linux/netlink.h"
#include "../include/linux/if_ether.h"

/* notifier_chain_register  */
#include "../include/linux/notifier.h"

/* copy_to/from_user() */
#include "../include/asm/uaccess.h"

/* __brlock_array __br_write_block  */
#include "../include/linux/brlock.h"
#include "../include/linux/smp.h"

/* kfree_skb() */
#include "../include/linux/skbuff.h"

#include "../include/linux/kernel.h"
#include "../include/linux/major.h"
#include "../include/linux/signal.h"
#include "../include/linux/errno.h"
#include "../include/linux/un.h"
#include "../include/linux/fcntl.h"
#include "../include/linux/termios.h"
#include "../include/linux/sockios.h"
#include "../include/linux/net.h"
#include "../include/linux/fs.h"
#include "../include/linux/slab.h"
#include "../include/linux/rtnetlink.h"
#include "../include/linux/proc_fs.h"
#include "../include/net/scm.h"

#include "../include/linux/ctype.h"
#include "../include/linux/sysctl.h"

#include "../include/linux/compiler.h"
#include "../include/net/ip_fib.h"

#include "../include/asm/string.h"
#include "../include/asm/semaphore.h"
#include "../include/asm/pgtable.h"

#include "../include/linux/spinlock.h"

struct ip_mib ip_statistics[NR_CPUS*2];

/* The 'big kernel lock' */
spinlock_cacheline_t kernel_flag_cacheline = {SPIN_LOCK_UNLOCKED};

struct proc_dir_entry *proc_sys_root;

static struct notifier_block *inetaddr_chain;
unsigned long max_mapnr;

unsigned long __supported_pte_mask = ~_PAGE_NX; 

/*temp*/
struct kernel_stat kstat;

/* Size description struct for general caches. */
typedef struct cache_sizes {
	size_t		 cs_size;
	kmem_cache_t	*cs_cachep;
	kmem_cache_t	*cs_dmacachep;
} cache_sizes_t;

static cache_sizes_t cache_sizes[] = {
#if PAGE_SIZE == 4096
	{    32,	NULL, NULL},
#endif
	{    64,	NULL, NULL},
	{   128,	NULL, NULL},
	{   256,	NULL, NULL},
	{   512,	NULL, NULL},
	{  1024,	NULL, NULL},
	{  2048,	NULL, NULL},
	{  4096,	NULL, NULL},
	{  8192,	NULL, NULL},
	{ 16384,	NULL, NULL},
	{ 32768,	NULL, NULL},
	{ 65536,	NULL, NULL},
	{131072,	NULL, NULL},
	{     0,	NULL, NULL}
};

#define BUFCTL_END 0xffffFFFF

#if STATS
#define	STATS_INC_ACTIVE(x)	((x)->num_active++)
#define	STATS_INC_ALLOCED(x)	((x)->num_allocations++)
#define	STATS_DEC_ACTIVE(x)	((x)->num_active--)
#define	STATS_SET_HIGH(x)	do { if ((x)->num_active > (x)->high_mark) \
					(x)->high_mark = (x)->num_active; \
				} while (0)
#else
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#endif

#if STATS && defined(CONFIG_SMP)
#define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
#define STATS_INC_ALLOCMISS(x)	atomic_inc(&(x)->allocmiss)
#else
#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#endif

static union {
	struct sk_buff_head	list;
	char			pad[SMP_CACHE_BYTES];
} skb_head_pool[NR_CPUS];

int sysctl_hot_list_len = 128;
static kmem_cache_t *skbuff_head_cache;

/* mem_map */
mem_map_t * mem_map;

int smp_num_cpus = 1;		/* Number that came online.  */

unsigned long volatile jiffies;

#define memcpy_tofs memcpy
#define memcpy_fromfs memcpy

rwlock_t notifier_lock = RW_LOCK_UNLOCKED;
/*
 *	Our notifier list
 */
static struct notifier_block *netdev_chain=NULL;

unsigned long num_physpages;

static struct softirq_action softirq_vec[32];

rwlock_t vmlist_lock = RW_LOCK_UNLOCKED;
struct vm_struct * vmlist;

#define CHECK_PAGE(pg)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#define	GET_PAGE_CACHE(pg)    ((kmem_cache_t *)(pg)->list.next)
#define	GET_PAGE_SLAB(pg)     ((slab_t *)(pg)->list.prev)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)

typedef unsigned int kmem_bufctl_t;

typedef struct cpucache_s {
	unsigned int avail;
	unsigned int limit;
} cpucache_t;

#define CACHE_NAMELEN	20	/* max name length for a slab cache */
struct kmem_cache_s {
/* 1) each alloc & free */
	/* full, partial first, then free */
	struct list_head	slabs_full;
	struct list_head	slabs_partial;
	struct list_head	slabs_free;
	unsigned int		objsize;
	unsigned int	 	flags;	/* constant flags */
	unsigned int		num;	/* # of objs per slab */
	spinlock_t		spinlock;
#ifdef CONFIG_SMP
	unsigned int		batchcount;
#endif

/* 2) slab additions /removals */
	/* order of pgs per slab (2^n) */
	unsigned int		gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	unsigned int		gfpflags;

	size_t			colour;		/* cache colouring range */
	unsigned int		colour_off;	/* colour offset */
	unsigned int		colour_next;	/* cache colouring */
	kmem_cache_t		*slabp_cache;
	unsigned int		growing;
	unsigned int		dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(void *, kmem_cache_t *, unsigned long);

	/* de-constructor func */
	void (*dtor)(void *, kmem_cache_t *, unsigned long);

	unsigned long		failures;

/* 3) cache creation/removal */
	char			name[CACHE_NAMELEN];
	struct list_head	next;
#ifdef CONFIG_SMP
/* 4) per-cpu data */
	cpucache_t		*cpudata[NR_CPUS];
#endif
#if STATS
	unsigned long		num_active;
	unsigned long		num_allocations;
	unsigned long		high_mark;
	unsigned long		grown;
	unsigned long		reaped;
	unsigned long 		errors;
#ifdef CONFIG_SMP
	atomic_t		allochit;
	atomic_t		allocmiss;
	atomic_t		freehit;
	atomic_t		freemiss;
#endif
#endif
};
typedef struct slab_s {
	struct list_head	list;
	unsigned long		colouroff;
	void			*s_mem;		/* including colour offset */
	unsigned int		inuse;		/* num of objs active in slab */
	kmem_bufctl_t		free;
} slab_t;

#define slab_bufctl(slabp) \
	((kmem_bufctl_t *)(((slab_t*)slabp)+1))

#define cc_entry(cpucache) \
	((void **)(((cpucache_t*)(cpucache))+1))
#define cc_data(cachep) \
	((cachep)->cpudata[smp_processor_id()])

static inline void kmem_cache_free_one(kmem_cache_t *cachep, void *objp)
{
	slab_t* slabp;

	CHECK_PAGE(virt_to_page(objp));
	/* reduces memory footprint
	 *
	if (OPTIMIZE(cachep))
		slabp = (void*)((unsigned long)objp&(~(PAGE_SIZE-1)));
	 else
	 */
	slabp = GET_PAGE_SLAB(virt_to_page(objp));

#if DEBUG
	if (cachep->flags & SLAB_DEBUG_INITIAL)
		/* Need to call the slab's constructor so the
		 * caller can perform a verify of its state (debugging).
		 * Called without the cache-lock held.
		 */
		cachep->ctor(objp, cachep, SLAB_CTOR_CONSTRUCTOR|SLAB_CTOR_VERIFY);

	if (cachep->flags & SLAB_RED_ZONE) {
		objp -= BYTES_PER_WORD;
		if (xchg((unsigned long *)objp, RED_MAGIC1) != RED_MAGIC2)
			/* Either write before start, or a double free. */
			BUG();
		if (xchg((unsigned long *)(objp+cachep->objsize -
				BYTES_PER_WORD), RED_MAGIC1) != RED_MAGIC2)
			/* Either write past end, or a double free. */
			BUG();
	}
	if (cachep->flags & SLAB_POISON)
		kmem_poison_obj(cachep, objp);
	if (kmem_extra_free_checks(cachep, slabp, objp))
		return;
#endif
	{
		unsigned int objnr = (objp-slabp->s_mem)/cachep->objsize;

		slab_bufctl(slabp)[objnr] = slabp->free;
		slabp->free = objnr;
	}
	STATS_DEC_ACTIVE(cachep);
	
	/* fixup slab chains */
	{
		int inuse = slabp->inuse;
		if (unlikely(!--slabp->inuse)) {
			/* Was partial or full, now empty. */
			list_del(&slabp->list);
			list_add(&slabp->list, &cachep->slabs_free);
		} else if (unlikely(inuse == cachep->num)) {
			/* Was full. */
			list_del(&slabp->list);
			list_add(&slabp->list, &cachep->slabs_partial);
		}
	}
}

static inline void __free_block (kmem_cache_t* cachep,
							void** objpp, int len)
{
	for ( ; len > 0; len--, objpp++)
		kmem_cache_free_one(cachep, *objpp);
}

static void free_block (kmem_cache_t* cachep, void** objpp, int len)
{
	spin_lock(&cachep->spinlock);
	__free_block(cachep, objpp, len);
	spin_unlock(&cachep->spinlock);
}

/* mm/slab.c */
static inline void __kmem_cache_free (kmem_cache_t *cachep, void* objp)
{
#ifdef CONFIG_SMP
	cpucache_t *cc = cc_data(cachep);

	CHECK_PAGE(virt_to_page(objp));
	if (cc) {
		int batchcount;
		if (cc->avail < cc->limit) {
			STATS_INC_FREEHIT(cachep);
			cc_entry(cc)[cc->avail++] = objp;
			return;
		}
		STATS_INC_FREEMISS(cachep);
		batchcount = cachep->batchcount;
		cc->avail -= batchcount;
		free_block(cachep,
					&cc_entry(cc)[cc->avail],batchcount);
		cc_entry(cc)[cc->avail++] = objp;
		return;
	} else {
		free_block(cachep, &objp, 1);
	}
#else
	kmem_cache_free_one(cachep, objp);
#endif
}

/** 
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 */
void kfree (const void *objp)
{
	kmem_cache_t *c;
	unsigned long flags;

	if (!objp)
		return;
	local_irq_save(flags);
	CHECK_PAGE(virt_to_page(objp));
	c = GET_PAGE_CACHE(virt_to_page(objp));
	__kmem_cache_free(c, (void*)objp);
	local_irq_restore(flags);
}
void vfree(void * addr)
{
	struct vm_struct **p, *tmp;

	if (!addr)
		return;
	if ((PAGE_SIZE-1) & (unsigned long) addr) {
//		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		return;
	}
	write_lock(&vmlist_lock);
	for (p = &vmlist ; (tmp = *p) ; p = &tmp->next) {
		if (tmp->addr == addr) {
			*p = tmp->next;
			vmfree_area_pages(VMALLOC_VMADDR(tmp->addr), tmp->size);
			write_unlock(&vmlist_lock);
			kfree(tmp);
			return;
		}
	}
	write_unlock(&vmlist_lock);
//	printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n", addr);
}
/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static inline void wakeup_softirqd(unsigned cpu)
{
	struct task_struct * tsk = ksoftirqd_task(cpu);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}
/* 
 * kernel/softirq.c
 */
void do_softirq_thunk()
{
	int cpu = smp_processor_id();
	__u32 pending;
	unsigned long flags;
	__u32 mask;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	pending = softirq_pending(cpu);

	if (pending) {
		struct softirq_action *h;

		mask = ~pending;
		local_bh_disable();
restart:
		/* Reset the pending bitmask before enabling irqs */
		softirq_pending(cpu) = 0;

		local_irq_enable();

		h = softirq_vec;

		do {
			if (pending & 1)
				h->action(h);
			h++;
			pending >>= 1;
		} while (pending);

		local_irq_disable();

		pending = softirq_pending(cpu);
		if (pending & mask) {
			mask &= ~pending;
			goto restart;
		}
		__local_bh_enable();

		if (pending)
			wakeup_softirqd(cpu);
	}

	local_irq_restore(flags);
}

static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct hh_cache *hh = dst->hh;

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_finish_output2(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	if (hh) {
		read_lock_bh(&hh->hh_lock);
  		memcpy(skb->data - 16, hh->hh_data, 16);
		read_unlock_bh(&hh->hh_lock);
	        skb_push(skb, hh->hh_len);
		return hh->hh_output(skb);
	} else if (dst->neighbour)
		return dst->neighbour->output(skb);

	if (net_ratelimit()){
//		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	}
	kfree_skb(skb);
	return -EINVAL;
}

__inline__ int ip_finish_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
		       ip_finish_output2);
}


int notifier_chain_register(struct notifier_block **list, struct notifier_block *n)
{
	write_lock(&notifier_lock);
	while(*list)
	{
		if(n->priority > (*list)->priority)
			break;
		list= &((*list)->next);
	}
	n->next = *list;
	*list=n;
	write_unlock(&notifier_lock);
	return 0;
}
int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n)
{
	write_lock(&notifier_lock);
	while((*nl)!=NULL)
	{
		if((*nl)==n)
		{
			*nl=n->next;
			write_unlock(&notifier_lock);
			return 0;
		}
		nl=&((*nl)->next);
	}
	write_unlock(&notifier_lock);
	return -ENOENT;
}
/*
 *	Device change register/unregister. These are not inline or static
 *	as we export them to the world.
 */
 
/**
 *	register_netdevice_notifier - register a network notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when network device events occur.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 */

int register_netdevice_notifier(struct notifier_block *nb)
{
	return notifier_chain_register(&netdev_chain, nb);
}
/**
 *	unregister_netdevice_notifier - unregister a network notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_netdevice_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 */

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&netdev_chain,nb);
}

unsigned long copy_from_user(void *to, const void *from_user, unsigned len)
{
	int	error;

	error = verify_area(VERIFY_READ, from_user, len);
	if (error)
		return len;
	memcpy_fromfs(to, from_user, len);
	return 0;
}

unsigned long copy_to_user(void *to_user, const void *from, unsigned len)
{
	int	error;
	
	error = verify_area(VERIFY_WRITE, to_user, len);
	if (error)
		return len;
	memcpy_tofs(to_user, from, len);
	return 0;
}

#ifdef CONFIG_SMP


#ifdef __BRLOCK_USE_ATOMICS

brlock_read_lock_t __brlock_array[NR_CPUS][__BR_IDX_MAX] =
   { [0 ... NR_CPUS-1] = { [0 ... __BR_IDX_MAX-1] = RW_LOCK_UNLOCKED } };

void __br_write_lock (enum brlock_indices idx)
{
	int i;

	for (i = 0; i < smp_num_cpus; i++)
		write_lock(&__brlock_array[cpu_logical_map(i)][idx]);
}

void __br_write_unlock (enum brlock_indices idx)
{
	int i;

	for (i = 0; i < smp_num_cpus; i++)
		write_unlock(&__brlock_array[cpu_logical_map(i)][idx]);
}

#else /* ! __BRLOCK_USE_ATOMICS */

brlock_read_lock_t __brlock_array[NR_CPUS][__BR_IDX_MAX] =
   { [0 ... NR_CPUS-1] = { [0 ... __BR_IDX_MAX-1] = 0 } };

struct br_wrlock __br_write_locks[__BR_IDX_MAX] =
   { [0 ... __BR_IDX_MAX-1] = { SPIN_LOCK_UNLOCKED } };

void __br_write_lock (enum brlock_indices idx)
{
	int i;

again:
	spin_lock(&__br_write_locks[idx].lock);
	for (i = 0; i < smp_num_cpus; i++)
		if (__brlock_array[cpu_logical_map(i)][idx] != 0) {
			spin_unlock(&__br_write_locks[idx].lock);
			barrier();
			cpu_relax();
			goto again;
		}
}

void __br_write_unlock (enum brlock_indices idx)
{
	spin_unlock(&__br_write_locks[idx].lock);
}

#endif /* __BRLOCK_USE_ATOMICS */

#endif /* CONFIG_SMP */

/*
 *	Slab constructor for a skb head. 
 */ 
/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */

void ip_options_fragment(struct sk_buff * skb) 
{
	/* temp */
}
static inline void skb_headerinit(void *p, kmem_cache_t *cache, 
				  unsigned long flags)
{
	struct sk_buff *skb = p;

	skb->next = NULL;
	skb->prev = NULL;
	skb->list = NULL;
	skb->sk = NULL;
	skb->stamp.tv_sec=0;	/* No idea about time */
	skb->dev = NULL;
	skb->dst = NULL;
	memset(skb->cb, 0, sizeof(skb->cb));
	skb->pkt_type = PACKET_HOST;	/* Default type */
	skb->ip_summed = 0;
	skb->priority = 0;
	skb->security = 0;	/* By default packets are insecure */
	skb->destructor = NULL;

#ifdef CONFIG_NETFILTER
	skb->nfmark = skb->nfcache = 0;
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
#endif
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#endif
}


/**
 *	__kfree_skb - private function 
 *	@skb: buffer
 *
 *	Free an sk_buff. Release anything attached to the buffer. 
 *	Clean the state. This is an internal helper function. Users should
 *	always call kfree_skb
 */
/*
 *	Free an skbuff by memory without cleaning the state. 
 */
static void skb_drop_fraglist(struct sk_buff *skb)
{
	struct sk_buff *list = skb_shinfo(skb)->frag_list;

	skb_shinfo(skb)->frag_list = NULL;

	do {
		struct sk_buff *this = list;
		list = list->next;
		kfree_skb(this);
	} while (list);
}

static void skb_release_data(struct sk_buff *skb)
{
	if (!skb->cloned ||
	    atomic_dec_and_test(&(skb_shinfo(skb)->dataref))) {
		if (skb_shinfo(skb)->nr_frags) {
			int i;
			for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
				put_page(skb_shinfo(skb)->frags[i].page);
		}

		if (skb_shinfo(skb)->frag_list)
			skb_drop_fraglist(skb);

		kfree(skb->head);
	}
}

static __inline__ void skb_head_to_pool(struct sk_buff *skb)
{
	struct sk_buff_head *list = &skb_head_pool[smp_processor_id()].list;

	if (skb_queue_len(list) < sysctl_hot_list_len) {
		unsigned long flags;

		local_irq_save(flags);
		__skb_queue_head(list, skb);
		local_irq_restore(flags);

		return;
	}
	kmem_cache_free(skbuff_head_cache, skb);
}
void kfree_skbmem(struct sk_buff *skb)
{
	skb_release_data(skb);
	skb_head_to_pool(skb);
}

void __kfree_skb(struct sk_buff *skb)
{
	if (skb->list) {
	 	// printk(KERN_WARNING "Warning: kfree_skb passed an skb still "
		//        "on a list (from %p).\n", NET_CALLER(skb));
		BUG();
	}

	dst_release(skb->dst);
	if(skb->destructor) {
		if (in_irq()) {
			// printk(KERN_WARNING "Warning: kfree_skb on hard IRQ %p\n",
			// 	NET_CALLER(skb));
		}
		skb->destructor(skb);
	}
#ifdef CONFIG_NETFILTER
	nf_conntrack_put(skb->nfct);
#endif
	skb_headerinit(skb, NULL, 0);  /* clean state */
	kfree_skbmem(skb);
}

void skb_under_panic(struct sk_buff *skb, int sz, void *here)
{
        // printk("skput:under: %p:%d put:%d dev:%s",
        //         here, skb->len, sz, skb->dev ? skb->dev->name : "<NULL>");
	BUG();
}


void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err)
{
	struct sk_buff *skb;
	struct nlmsghdr *rep;
	struct nlmsgerr *errmsg;
	int size;

	if (err == 0)
		size = NLMSG_SPACE(sizeof(struct nlmsgerr));
	else
		size = NLMSG_SPACE(4 + NLMSG_ALIGN(nlh->nlmsg_len));

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return;

	rep = __nlmsg_put(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
			  NLMSG_ERROR, sizeof(struct nlmsgerr));
	errmsg = NLMSG_DATA(rep);
	errmsg->error = err;
	memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(struct nlmsghdr));
	netlink_unicast(in_skb->sk, skb, NETLINK_CB(in_skb).pid, MSG_DONTWAIT);
}


/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't a great routine, but it's not _horrible_ either. 
 * We rely on the compiler to unroll.
 */
/* Better way for this sought */
static inline unsigned short from64to16(unsigned long x)
{
	/* add up 32-bit words for 33 bits */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up 16-bit and 17-bit words for 17+c bits */
	x = (x & 0xffff) + (x >> 16);
	/* add up 16-bit and 2-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static inline unsigned do_csum(const unsigned char * buff, int len)
{
	int odd, count;
	unsigned long result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (unlikely(odd)) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */
			if (count) {
				unsigned long zero = 0; 
				do {
					asm("  addq %1,%0\n"
					    "  adcq %2,%0\n" 
					    : "=r" (result)
					    : "m"  (*buff), "r" (zero),  "0" (result));
					count--;
					buff += 8;
				} while (count);
				result = (result & 0xffffffff) + (result >> 32);
			}
			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = from64to16(result);
	if (unlikely(odd))
		return ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}
/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
unsigned short ip_compute_csum(unsigned char * buff, int len)
{
	return ~do_csum(buff,len);
}

/**
 * strnicmp - Case insensitive, length-limited string comparison
 * @s1: One string
 * @s2: The other string
 * @len: the maximum number of characters to compare
 */
int strnicmp(const char *s1, const char *s2, size_t len)
{
	/* Yes, Virginia, it had better be unsigned */
	unsigned char c1, c2;

	c1 = 0;	c2 = 0;
	if (len) {
		do {
			c1 = *s1; c2 = *s2;
			s1++; s2++;
			if (!c1)
				break;
			if (!c2)
				break;
			if (c1 == c2)
				continue;
			c1 = tolower(c1);
			c2 = tolower(c2);
			if (c1 != c2)
				break;
		} while (--len);
	}
	return (int)c1 - (int)c2;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum)
{
	unsigned long result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	/* 32+c bits -> 32 bits */
	result = (result & 0xffffffff) + (result >> 32);
	return result;
}

int proc_dointvec(ctl_table *table, int write, struct file *filp,
		  void *buffer, size_t *lenp)
{
	return -ENOSYS;
}

/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * kmalloc is the normal method of allocating memory
 * in the kernel.
 *
 * The @flags argument may be one of:
 *
 * %GFP_USER - Allocate memory on behalf of user.  May sleep.
 *
 * %GFP_KERNEL - Allocate normal kernel ram.  May sleep.
 *
 * %GFP_ATOMIC - Allocation will not sleep.  Use inside interrupt handlers.
 *
 * Additionally, the %GFP_DMA flag may be set to indicate the memory
 * must be suitable for DMA.  This can mean different things on different
 * platforms.  For example, on i386, it means that the memory must come
 * from the first 16MB.
 */
static inline void * kmem_cache_alloc_one_tail (kmem_cache_t *cachep,
						slab_t *slabp)
{
	void *objp;

	STATS_INC_ALLOCED(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	/* get obj pointer */
	slabp->inuse++;
	objp = slabp->s_mem + slabp->free*cachep->objsize;
	slabp->free=slab_bufctl(slabp)[slabp->free];

	if (unlikely(slabp->free == BUFCTL_END)) {
		list_del(&slabp->list);
		list_add(&slabp->list, &cachep->slabs_full);
	}
#if DEBUG
	if (cachep->flags & SLAB_POISON)
		if (kmem_check_poison_obj(cachep, objp))
			BUG();
	if (cachep->flags & SLAB_RED_ZONE) {
		/* Set alloc red-zone, and check old one. */
		if (xchg((unsigned long *)objp, RED_MAGIC2) !=
							 RED_MAGIC1)
			BUG();
		if (xchg((unsigned long *)(objp+cachep->objsize -
			  BYTES_PER_WORD), RED_MAGIC2) != RED_MAGIC1)
			BUG();
		objp += BYTES_PER_WORD;
	}
#endif
	return objp;
}
#define kmem_cache_alloc_one(cachep)				\
({								\
	struct list_head * slabs_partial, * entry;		\
	slab_t *slabp;						\
								\
	slabs_partial = &(cachep)->slabs_partial;		\
	entry = slabs_partial->next;				\
	if (unlikely(entry == slabs_partial)) {			\
		struct list_head * slabs_free;			\
		slabs_free = &(cachep)->slabs_free;		\
		entry = slabs_free->next;			\
		if (unlikely(entry == slabs_free))		\
			goto alloc_new_slab;			\
		list_del(entry);				\
		list_add(entry, slabs_partial);			\
	}							\
								\
	slabp = list_entry(entry, slab_t, list);		\
	kmem_cache_alloc_one_tail(cachep, slabp);		\
})

static inline void kmem_cache_alloc_head(kmem_cache_t *cachep, int flags)
{
	if (flags & SLAB_DMA) {
		if (!(cachep->gfpflags & GFP_DMA))
			BUG();
	} else {
		if (cachep->gfpflags & GFP_DMA)
			BUG();
	}
}

void* kmem_cache_alloc_batch(kmem_cache_t* cachep, cpucache_t* cc, int flags)
{
	int batchcount = cachep->batchcount;

	spin_lock(&cachep->spinlock);
	while (batchcount--) {
		struct list_head * slabs_partial, * entry;
		slab_t *slabp;
		/* Get slab alloc is to come from. */
		slabs_partial = &(cachep)->slabs_partial;
		entry = slabs_partial->next;
		if (unlikely(entry == slabs_partial)) {
			struct list_head * slabs_free;
			slabs_free = &(cachep)->slabs_free;
			entry = slabs_free->next;
			if (unlikely(entry == slabs_free))
				break;
			list_del(entry);
			list_add(entry, slabs_partial);
		}

		slabp = list_entry(entry, slab_t, list);
		cc_entry(cc)[cc->avail++] =
				kmem_cache_alloc_one_tail(cachep, slabp);
	}
	spin_unlock(&cachep->spinlock);

	if (cc->avail)
		return cc_entry(cc)[--cc->avail];
	return NULL;
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 */
static int kmem_cache_grow (kmem_cache_t * cachep, int flags)
{
	return 0;
}

static inline void * __kmem_cache_alloc (kmem_cache_t *cachep, int flags)
{
	unsigned long save_flags;
	void* objp;

	kmem_cache_alloc_head(cachep, flags);
try_again:
	local_irq_save(save_flags);
#ifdef CONFIG_SMP
	{
		cpucache_t *cc = cc_data(cachep);

		if (cc) {
			if (cc->avail) {
				STATS_INC_ALLOCHIT(cachep);
				objp = cc_entry(cc)[--cc->avail];
			} else {
				STATS_INC_ALLOCMISS(cachep);
				objp = kmem_cache_alloc_batch(cachep,cc,flags);
				if (!objp)
					goto alloc_new_slab_nolock;
			}
		} else {
			spin_lock(&cachep->spinlock);
			objp = kmem_cache_alloc_one(cachep);
			spin_unlock(&cachep->spinlock);
		}
	}
#else
	objp = kmem_cache_alloc_one(cachep);
#endif
	local_irq_restore(save_flags);
	return objp;
alloc_new_slab:
#ifdef CONFIG_SMP
	spin_unlock(&cachep->spinlock);
alloc_new_slab_nolock:
#endif
	local_irq_restore(save_flags);
	if (kmem_cache_grow(cachep, flags))
		/* Someone may have stolen our objs.  Doesn't matter, we'll
		 * just come back here again.
		 */
		goto try_again;
	return NULL;
}

void * kmalloc (size_t size, int flags)
{
	cache_sizes_t *csizep = cache_sizes;

	for (; csizep->cs_size; csizep++) {
		if (size > csizep->cs_size)
			continue;
		return __kmem_cache_alloc(flags & GFP_DMA ?
			 csizep->cs_dmacachep : csizep->cs_cachep, flags);
	}
	return NULL;
}

void * __vmalloc (unsigned long size, int gfp_mask, pgprot_t prot)
{
	
}

int ip_route_output_key(struct rtable **rp, const struct rt_key *key)
{

	return 0;
}

inline void * __memcpy(void * to, const void * from, size_t n)
{	

}

struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
					 struct proc_dir_entry *parent)
{
	return NULL;
}

/*
 * Remove a /proc entry and free it if it's not currently in use.
 * If it is in use, we set the 'deleted' flag.
 */
void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{

}

/**
 * request_module - try to load a kernel module
 * @module_name: Name of module
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code on failure. Note that a
 * successful module load does not mean the module did not then unload
 * and exit on an error of its own. Callers must check that the service
 * they requested is now available not blindly invoke it.
 *
 * If module auto-loading support is disabled then this function
 * becomes a no-operation.
 */
int request_module(const char * module_name)
{

	return 0;
}
/*
 * Perform the "down" function.  Return zero for semaphore acquired,
 * return negative for signalled out of the function.
 *
 * If called from down, the return is ignored and the wait loop is
 * not interruptible.  This means that a task waiting on a semaphore
 * using "down()" cannot be killed until someone does an "up()" on
 * the semaphore.
 *
 * If called from down_interruptible, the return value gets checked
 * upon return.  If the return value is negative then the task continues
 * with the negative value in the return register (it can be tested by
 * the caller).
 *
 * Either form may be used in conjunction with "up()".
 */

void
__down_failed(void)  /* special register calling convention */
{

}

int
__down_failed_interruptible(void) /* params in registers */
{

	return 0;
}

void
__up_wakeup(void)
{
	
}

void __write_lock_failed(void)
{
/* temp */

}
void __read_lock_failed(void)
{
/* temp */

}

void __br_lock_usage_bug (void)
{
/* temp */

}

int net_ratelimit(void)
{
/* temp */
	return 1;
}

/**
 *	netdev_finish_unregister - complete unregistration
 *	@dev: device
 *
 *	Destroy and free a dead device. A value of zero is returned on
 *	success.
 */
 
int netdev_finish_unregister(struct net_device *dev)
{

	return 0;
}
/**
 *	skb_over_panic	- 	private function
 *	@skb: buffer
 *	@sz: size
 *	@here: address
 *
 *	Out of line support code for skb_put(). Not user callable.
 */
 
void skb_over_panic(struct sk_buff *skb, int sz, void *here)
{
	// printk("skput:over: %p:%d put:%d dev:%s", 
	// 	here, skb->len, sz, skb->dev ? skb->dev->name : "<NULL>");
	BUG();
}

int del_timer(struct timer_list * timer)
{
	return 1;
}

/**
 * A BUG() call in an inline function in a header should be avoided,
 * because it can seriously bloat the kernel.  So here we have
 * helper functions.
 * We lose the BUG()-time file-and-line info this way, but it's
 * usually not very useful from an inline anyway.  The backtrace
 * tells us what we want to know.
 */

void __out_of_line_bug(int line)
{
	// printk("kernel BUG in header file at line %d\n", line);

	BUG();

	/* Satisfy __attribute__((noreturn)) */
	for ( ; ; )
		;
}

/* 
 * net_netlink.c
 */
void netlink_broadcast(struct sock *ssk, struct sk_buff *skb, u32 pid,
		       u32 group, int allocation)
{
	/* temp */
}

static __inline__ struct sk_buff *skb_head_from_pool(void)
{
	struct sk_buff_head *list = &skb_head_pool[smp_processor_id()].list;

	if (skb_queue_len(list)) {
		struct sk_buff *skb;
		unsigned long flags;

		local_irq_save(flags);
		skb = __skb_dequeue(list);
		local_irq_restore(flags);
		return skb;
	}
	return NULL;
}
struct sk_buff *alloc_skb(unsigned int size,int gfp_mask)
{
		struct sk_buff *skb;
	u8 *data;

	if (in_interrupt() && (gfp_mask & __GFP_WAIT)) {
		static int count = 0;
		if (++count < 5) {
			// printk(KERN_ERR "alloc_skb called nonatomically "
			//        "from interrupt %p\n", NET_CALLER(size));
 			BUG();
		}
		gfp_mask &= ~__GFP_WAIT;
	}

	/* Get the HEAD */
	skb = skb_head_from_pool();
	if (skb == NULL) {
		skb = kmem_cache_alloc(skbuff_head_cache, gfp_mask & ~__GFP_DMA);
		if (skb == NULL)
			goto nohead;
	}

	/* Get the DATA. Size must match skb_add_mtu(). */
	size = SKB_DATA_ALIGN(size);
	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (data == NULL)
		goto nodata;

	/* XXX: does not include slab overhead */ 
	skb->truesize = size + sizeof(struct sk_buff);

	/* Load the data pointers. */
	skb->head = data;
	skb->data = data;
	skb->tail = data;
	skb->end = data + size;

	/* Set up other state */
	skb->len = 0;
	skb->cloned = 0;
	skb->data_len = 0;

	atomic_set(&skb->users, 1); 
	atomic_set(&(skb_shinfo(skb)->dataref), 1);
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;
	return skb;

nodata:
	skb_head_to_pool(skb);
nohead:
	/* temp */
	return NULL;
}

/*
 * net_netlink.c
 *	We export these functions to other modules. They provide a 
 *	complete set of kernel non-blocking support for message
 *	queueing.
 */

struct sock *
netlink_kernel_create(int unit, void (*input)(struct sock *sk, int len))
{
	/* temp */
	return NULL;
}

/**
 *	sock_release	-	close a socket
 *	@sock: socket to close
 *
 *	The socket is released from the protocol stack if it has a release
 *	callback, and the inode is then released if the socket is bound to
 *	an inode not a file. 
 */
 /*
 *	Statistics counters of the socket lists
 */

static union {
	int	counter;
	char	__pad[SMP_CACHE_BYTES];
} sockets_in_use[NR_CPUS];


/**
 *	iput	- put an inode 
 *	@inode: inode to put
 *
 *	Puts an inode, dropping its usage count. If the inode use count hits
 *	zero the inode is also then freed and may be destroyed.
 */
 
void iput(struct inode *inode)
{
	/* temp */
}

void sock_release(struct socket *sock)
{
	if (sock->ops) 
		sock->ops->release(sock);

	if (sock->fasync_list) {
//		printk(KERN_ERR "sock_release: fasync list not empty!\n");
	}

	sockets_in_use[smp_processor_id()].counter--;
	if (!sock->file) {
		iput(sock->inode);
		return;
	}
	sock->file=NULL;
}

/* Initialize both explicitly - let's try to have them in the same cache line */
spinlock_t timerlist_lock = SPIN_LOCK_UNLOCKED;
static unsigned long timer_jiffies;
static struct list_head * run_timer_list_running;

/*
 * Event timer code
 */
#define TVN_BITS 6
#define TVR_BITS 8
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

struct timer_vec {
	int index;
	struct list_head vec[TVN_SIZE];
};

struct timer_vec_root {
	int index;
	struct list_head vec[TVR_SIZE];
};

static struct timer_vec tv5;
static struct timer_vec tv4;
static struct timer_vec tv3;
static struct timer_vec tv2;
static struct timer_vec_root tv1;


static inline void internal_add_timer(struct timer_list *timer)
{
	/*
	 * must be cli-ed when calling this
	 */
	unsigned long expires = timer->expires;
	unsigned long idx = expires - timer_jiffies;
	struct list_head * vec;

	if (run_timer_list_running)
		vec = run_timer_list_running;
	else if (idx < TVR_SIZE) {
		int i = expires & TVR_MASK;
		vec = tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		int i = (expires >> TVR_BITS) & TVN_MASK;
		vec = tv2.vec + i;
	} else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec =  tv3.vec + i;
	} else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
		vec = tv4.vec + i;
	} else if ((signed long) idx < 0) {
		/* can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
		vec = tv1.vec + tv1.index;
	} else if (idx <= 0xffffffffUL) {
		int i = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
		vec = tv5.vec + i;
	} else {
		/* Can only get here on architectures with 64-bit jiffies */
		INIT_LIST_HEAD(&timer->list);
		return;
	}
	/*
	 * Timers are FIFO!
	 */
	list_add(&timer->list, vec->prev);
}
void add_timer(struct timer_list *timer)
{
	unsigned long flags;

	spin_lock_irqsave(&timerlist_lock, flags);
	if (timer_pending(timer))
		goto bug;
	internal_add_timer(timer);
	spin_unlock_irqrestore(&timerlist_lock, flags);
	return;
bug:
	spin_unlock_irqrestore(&timerlist_lock, flags);
	// printk("bug: kernel timer added twice at %p.\n",
	// 		__builtin_return_address(0));
}

/* skbuff.c
 * Trims skb to length len. It can change skb pointers, if "realloc" is 1.
 * If realloc==0 and trimming is impossible without change of data,
 * it is BUG().
 */

int ___pskb_trim(struct sk_buff *skb, unsigned int len, int realloc)
{
	/* temp */
	return 0;
}

/* net/ipv4/route.c */
/*
 * This function is the exported kernel interface.  It returns some
 * number of good random numbers, suitable for seeding TCP sequence
 * numbers, etc.
 */
static struct entropy_store *random_state; /* The default global store */
static struct entropy_store *sec_random_state; /* secondary store */
#define EXTRACT_ENTROPY_SECONDARY	2

static ssize_t extract_entropy(struct entropy_store *r, void * buf,
			       size_t nbytes, int flags)
{
	/* temp */
	return 0;
}
void get_random_bytes(void *buf, int nbytes)
{
	if (sec_random_state)  
		extract_entropy(sec_random_state, (char *) buf, nbytes, 
				EXTRACT_ENTROPY_SECONDARY);
	else if (random_state)
		extract_entropy(random_state, (char *) buf, nbytes, 0);
	else {
		// printk(KERN_NOTICE "get_random_bytes called before "
		// 		   "random driver initialization\n");
	}
}

/*  The code below is shamelessly stolen from secure_tcp_sequence_number().
 *  All blames to Andrey V. Savochkin <saw@msu.ru>.
 */

/* This should not be decreased so low that ISNs wrap too fast. */
#define REKEY_INTERVAL	300
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & (y)) + (((x) ^ (y)) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/*
 * The generic round function.  The application is so specific that
 * we don't bother protecting all the arguments with parens, as is generally
 * good macro practice, in favor of extra legibility.
 * Rotation is separate from addition to prevent recomputation
 */
#define ROUND(f, a, b, c, d, x, s)	\
	(a += f(b, c, d) + x, a = (a << s) | (a >> (32-s)))
#define K1 0
#define K2 013240474631UL
#define K3 015666365641UL

/*
 * Basic cut-down MD4 transform.  Returns only 32 bits of result.
 */
static __u32 halfMD4Transform (__u32 const buf[4], __u32 const in[8])
{
	__u32	a = buf[0], b = buf[1], c = buf[2], d = buf[3];

	/* Round 1 */
	ROUND(F, a, b, c, d, in[0] + K1,  3);
	ROUND(F, d, a, b, c, in[1] + K1,  7);
	ROUND(F, c, d, a, b, in[2] + K1, 11);
	ROUND(F, b, c, d, a, in[3] + K1, 19);
	ROUND(F, a, b, c, d, in[4] + K1,  3);
	ROUND(F, d, a, b, c, in[5] + K1,  7);
	ROUND(F, c, d, a, b, in[6] + K1, 11);
	ROUND(F, b, c, d, a, in[7] + K1, 19);

	/* Round 2 */
	ROUND(G, a, b, c, d, in[1] + K2,  3);
	ROUND(G, d, a, b, c, in[3] + K2,  5);
	ROUND(G, c, d, a, b, in[5] + K2,  9);
	ROUND(G, b, c, d, a, in[7] + K2, 13);
	ROUND(G, a, b, c, d, in[0] + K2,  3);
	ROUND(G, d, a, b, c, in[2] + K2,  5);
	ROUND(G, c, d, a, b, in[4] + K2,  9);
	ROUND(G, b, c, d, a, in[6] + K2, 13);

	/* Round 3 */
	ROUND(H, a, b, c, d, in[3] + K3,  3);
	ROUND(H, d, a, b, c, in[7] + K3,  9);
	ROUND(H, c, d, a, b, in[2] + K3, 11);
	ROUND(H, b, c, d, a, in[6] + K3, 15);
	ROUND(H, a, b, c, d, in[1] + K3,  3);
	ROUND(H, d, a, b, c, in[5] + K3,  9);
	ROUND(H, c, d, a, b, in[0] + K3, 11);
	ROUND(H, b, c, d, a, in[4] + K3, 15);

	return buf[1] + b;	/* "most hashed" word */
	/* Alternative: return sum of all words? */
}

__u32 secure_ip_id(__u32 daddr)
{
	static time_t	rekey_time;
	static __u32	secret[12];
	time_t		t;

	/*
	 * Pick a random secret every REKEY_INTERVAL seconds.
	 */
	struct timeval xtime_tmp;
	//t = CURRENT_TIME;
	t = xtime_tmp.tv_sec;
	if (!rekey_time || (t - rekey_time) > REKEY_INTERVAL) {
		rekey_time = t;
		/* First word is overwritten below. */
		get_random_bytes(secret+1, sizeof(secret)-4);
	}

	/*
	 *  Pick a unique starting offset for each IP destination.
	 *  Note that the words are placed into the first words to be
	 *  mixed in with the halfMD4.  This is because the starting
	 *  vector is also a random secret (at secret+8), and further
	 *  hashing fixed data into it isn't going to improve anything,
	 *  so we should get started with the variable data.
	 */
	secret[0]=daddr;

	return halfMD4Transform(secret+8, secret);
}
/*
 * Peer allocation may fail only in serious out-of-memory conditions.  However
 * we still can generate some output.
 * Random ID selection looks a bit dangerous because we have no chances to
 * select ID being unique in a reasonable period of time.
 * But broken packet identifier may be better than no packet at all.
 */
static void ip_select_fb_ident(struct iphdr *iph)
{
	static spinlock_t ip_fb_id_lock = SPIN_LOCK_UNLOCKED;
	static u32 ip_fallback_id;
	u32 salt;

	spin_lock_bh(&ip_fb_id_lock);
	salt = secure_ip_id(ip_fallback_id ^ iph->daddr);
	iph->id = htons(salt & 0xFFFF);
	ip_fallback_id = salt;
	spin_unlock_bh(&ip_fb_id_lock);
}
/* Called with or without local BH being disabled. */
struct inet_peer *inet_getpeer(__u32 daddr, int create)
{
	return NULL;
}
void rt_bind_peer(struct rtable *rt, int create)
{
	static spinlock_t rt_peer_lock = SPIN_LOCK_UNLOCKED;
	struct inet_peer *peer;

	peer = inet_getpeer(rt->rt_dst, create);

	spin_lock_bh(&rt_peer_lock);
	if (rt->peer == NULL) {
		rt->peer = peer;
		peer = NULL;
	}
	spin_unlock_bh(&rt_peer_lock);
	if (peer)
		inet_putpeer(peer);
}
void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *) dst;

	if (rt) {
		if (rt->peer == NULL)
			rt_bind_peer(rt, 1);

		/* If peer is attached to destination, it is never detached,
		   so that we need not to grab a lock to dereference it.
		 */
		if (rt->peer) {
			iph->id = htons(inet_getid(rt->peer));
			return;
		}
	} else{
//		printk(KERN_DEBUG "rt_bind_peer(0) @%p\n", NET_CALLER(iph));
	}

	ip_select_fb_ident(iph);
}

/**
 *	skb_copy	-	create private copy of an sk_buff
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data. This is used when the
 *	caller wishes to modify the data and needs a private copy of the 
 *	data to alter. Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	As by-product this function converts non-linear &sk_buff to linear
 *	one, so that &sk_buff becomes completely private and caller is allowed
 *	to modify all the data of returned buffer. This means that this
 *	function is not recommended for use in circumstances when only
 *	header is going to be modified. Use pskb_copy() instead.
 */
 static void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	/*
	 *	Shift between the two data areas in bytes
	 */
	unsigned long offset = new->data - old->data;

	new->list=NULL;
	new->sk=NULL;
	new->dev=old->dev;
	new->priority=old->priority;
	new->protocol=old->protocol;
	new->dst=dst_clone(old->dst);
	new->h.raw=old->h.raw+offset;
	new->nh.raw=old->nh.raw+offset;
	new->mac.raw=old->mac.raw+offset;
	memcpy(new->cb, old->cb, sizeof(old->cb));
	atomic_set(&new->users, 1);
	new->pkt_type=old->pkt_type;
	new->stamp=old->stamp;
	new->destructor = NULL;
	new->security=old->security;
#ifdef CONFIG_NETFILTER
	new->nfmark=old->nfmark;
	new->nfcache=old->nfcache;
	new->nfct=old->nfct;
	nf_conntrack_get(new->nfct);
#ifdef CONFIG_NETFILTER_DEBUG
	new->nf_debug=old->nf_debug;
#endif
#endif
#ifdef CONFIG_NET_SCHED
	new->tc_index = old->tc_index;
#endif
}
/* Copy some data bits from skb to kernel buffer. */

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
	return 0;
}
struct sk_buff *skb_copy(const struct sk_buff *skb, int gfp_mask)
{
	struct sk_buff *n;
	int headerlen = skb->data-skb->head;

	/*
	 *	Allocate the copy buffer
	 */
	n=alloc_skb(skb->end - skb->head + skb->data_len, gfp_mask);
	if(n==NULL)
		return NULL;

	/* Set the data pointer */
	skb_reserve(n,headerlen);
	/* Set the tail pointer and length */
	skb_put(n,skb->len);
	n->csum = skb->csum;
	n->ip_summed = skb->ip_summed;

	if (skb_copy_bits(skb, -headerlen, n->head, headerlen+skb->len))
		BUG();

	copy_skb_header(n, skb);

	return n;
}
/*
 *	Check transmit rate limitation for given message.
 *	The rate information is held in the destination cache now.
 *	This function is generic and could be used for other purposes
 *	too. It uses a Token bucket filter as suggested by Alexey Kuznetsov.
 *
 *	Note that the same dst_entry fields are modified by functions in 
 *	route.c too, but these work for packet destinations while xrlim_allow
 *	works for icmp destinations. This means the rate limiting information
 *	for one "ip object" is shared - and these ICMPs are twice limited:
 *	by source and by destination.
 *
 *	RFC 1812: 4.3.2.8 SHOULD be able to limit error message rate
 *			  SHOULD allow setting of rate limits 
 *
 * 	Shared between ICMPv4 and ICMPv6.
 */
#define XRLIM_BURST_FACTOR 6
int xrlim_allow(struct dst_entry *dst, int timeout)
{
	unsigned long now;

	now = jiffies;
	dst->rate_tokens += now - dst->rate_last;
	dst->rate_last = now;
	if (dst->rate_tokens > XRLIM_BURST_FACTOR*timeout)
        	dst->rate_tokens = XRLIM_BURST_FACTOR*timeout;
	if (dst->rate_tokens >= timeout) {
		dst->rate_tokens -= timeout;
		return 1;
	}
	return 0; 
}

/*
 *	Device notifier
 */

int register_inetaddr_notifier(struct notifier_block *nb)
{
	return notifier_chain_register(&inetaddr_chain, nb);
}

int unregister_inetaddr_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&inetaddr_chain,nb);
}

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
static kmem_cache_t *sk_cachep;
/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
	unsigned long result = 0,value;

	if (!base) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if ((*cp == 'x') && isxdigit(cp[1])) {
				cp++;
				base = 16;
			}
		}
	}
	while (isxdigit(*cp) &&
	       (value = isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

void sk_free(struct sock *sk)
{
#ifdef CONFIG_FILTER
	struct sk_filter *filter;
#endif

	if (sk->destruct)
		sk->destruct(sk);

#ifdef CONFIG_FILTER
	filter = sk->filter;
	if (filter) {
		sk_filter_release(sk, filter);
		sk->filter = NULL;
	}
#endif

	if (atomic_read(&sk->omem_alloc)){
//		printk(KERN_DEBUG "sk_free: optmem leakage (%d bytes) detected.\n", atomic_read(&sk->omem_alloc));
	}

	kmem_cache_free(sk_cachep, sk);
}
/* 
 * Write buffer destructor automatically called from kfree_skb. 
 */
void sock_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	/* In case it might be waiting for more memory. */
	atomic_sub(skb->truesize, &sk->wmem_alloc);
	if (!sk->use_write_queue)
		sk->write_space(sk);
	sock_put(sk);
}

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free (kmem_cache_t *cachep, void *objp)
{
	unsigned long flags;
#if DEBUG
	CHECK_PAGE(virt_to_page(objp));
	if (cachep != GET_PAGE_CACHE(virt_to_page(objp)))
		BUG();
#endif

	local_irq_save(flags);
	__kmem_cache_free(cachep, objp);
	local_irq_restore(flags);
}

/* Process an incoming IP datagram fragment. */
struct sk_buff *ip_defrag(struct sk_buff *skb)
{
	/* temp */
	return NULL;
}


/* Keep head the same: replace data */
int skb_linearize(struct sk_buff *skb, int gfp_mask)
{
	unsigned int size;
	u8 *data;
	long offset;
	int headerlen = skb->data - skb->head;
	int expand = (skb->tail+skb->data_len) - skb->end;

	if (skb_shared(skb))
		BUG();

	if (expand <= 0)
		expand = 0;

	size = (skb->end - skb->head + expand);
	size = SKB_DATA_ALIGN(size);
	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (data == NULL)
		return -ENOMEM;

	/* Copy entire thing */
	if (skb_copy_bits(skb, -headerlen, data, headerlen+skb->len))
		BUG();

	/* Offset between the two in bytes */
	offset = data - skb->head;

	/* Free old data. */
	skb_release_data(skb);

	skb->head = data;
	skb->end  = data + size;

	/* Set up new pointers */
	skb->h.raw += offset;
	skb->nh.raw += offset;
	skb->mac.raw += offset;
	skb->tail += offset;
	skb->data += offset;

	/* Set up shinfo */
	atomic_set(&(skb_shinfo(skb)->dataref), 1);
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;

	/* We are no longer a clone, even if we were. */
	skb->cloned = 0;

	skb->tail += skb->data_len;
	skb->data_len = 0;
	return 0;
}

/* Generate a checksum for an outgoing IP datagram. */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}


/*
 * Unregister a /proc sysctl table and any subdirectories.
 */
static void unregister_proc_table(ctl_table * table, struct proc_dir_entry *root)
{
	struct proc_dir_entry *de;
	for (; table->ctl_name; table++) {
		if (!(de = table->de))
			continue;
		if (de->mode & S_IFDIR) {
			if (!table->child) {
//				printk (KERN_ALERT "Help - malformed sysctl tree on free\n");
				continue;
			}
			unregister_proc_table(table->child, de);

			/* Don't unregister directories which still have entries.. */
			if (de->subdir)
				continue;
		}

		/* Don't unregister proc entries that are still being used.. */
		if (atomic_read(&de->count))
			continue;

		table->de = NULL;
		remove_proc_entry(table->procname, root);
	}
}
/**
 * unregister_sysctl_table - unregister a sysctl table hierarchy
 * @header: the header returned from register_sysctl_table
 *
 * Unregisters the sysctl table and all children. proc entries may not
 * actually be removed until they are no longer used by anyone.
 */
void unregister_sysctl_table(struct ctl_table_header * header)
{
	list_del(&header->ctl_entry);
#ifdef CONFIG_PROC_FS
	unregister_proc_table(header->ctl_table, proc_sys_root);
#endif
	kfree(header);
}

void schedule(void)
{
	/* temp */
}
/**
 * kmem_cache_destroy - delete a cache
 * @cachep: the cache to destroy
 *
 * Remove a kmem_cache_t object from the slab cache.
 * Returns 0 on success.
 *
 * It is expected this function will be called by a module when it is
 * unloaded.  This will remove the cache completely, and avoid a duplicate
 * cache being allocated each time a module is loaded and unloaded, if the
 * module doesn't have persistent in-kernel storage across loads and unloads.
 *
 * The caller must guarantee that noone will allocate memory from the cache
 * during the kmem_cache_destroy().
 */
int kmem_cache_destroy (kmem_cache_t * cachep)
{
	/* temp */
	return 0;
}

/* Scan the sysctl entries in table and add them all into /proc */
static void register_proc_table(ctl_table * table, struct proc_dir_entry *root)
{
	/* may not be used*/
}

static ctl_table root_table[] = {0};       /* temp */
static struct ctl_table_header root_table_header =
	{ root_table, LIST_HEAD_INIT(root_table_header.ctl_entry) };


struct ctl_table_header *register_sysctl_table(ctl_table * table, 
					       int insert_at_head)
{
		struct ctl_table_header *tmp;
	tmp = kmalloc(sizeof(struct ctl_table_header), GFP_KERNEL);
	if (!tmp)
		return NULL;
	tmp->ctl_table = table;
	INIT_LIST_HEAD(&tmp->ctl_entry);
	if (insert_at_head)
		list_add(&tmp->ctl_entry, &root_table_header.ctl_entry);
	else
		list_add_tail(&tmp->ctl_entry, &root_table_header.ctl_entry);
#ifdef CONFIG_PROC_FS
	register_proc_table(table, proc_sys_root);
#endif
	return tmp;
}

static inline void free_area_pte(pmd_t * pmd, unsigned long address, unsigned long size)
{
	pte_t * pte;
	unsigned long end;

	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
	//	pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}
	pte = pte_offset(pmd, address);
	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		pte_t page;
		page = ptep_get_and_clear(pte);
		address += PAGE_SIZE;
		pte++;
		if (pte_none(page))
			continue;
		if (pte_present(page)) {
			struct page *ptpage = pte_page(page);
			if (VALID_PAGE(ptpage) && (!PageReserved(ptpage)))
				__free_page(ptpage);
			continue;
		}
//		printk(KERN_CRIT "Whee.. Swapped out page in kernel page table\n");
	} while (address < end);
}

static inline void free_area_pmd(pgd_t * dir, unsigned long address, unsigned long size)
{
	pmd_t * pmd;
	unsigned long end;

	if (pgd_none(*dir))
		return;
	if (pgd_bad(*dir)) {
	//	pgd_ERROR(*dir);
		pgd_clear(dir);
		return;
	}
	pmd = pmd_offset(dir, address);
	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		free_area_pte(pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
}


void
flush_tlb_all(void)
{
	return;
}

/* temp */
pml4_t init_level4_pgt[] = {0};

void vmfree_area_pages(unsigned long address, unsigned long size)
{
	pgd_t * dir;
	unsigned long end = address + size;

	dir = pgd_offset_k(address);
	flush_cache_all();
	do {
		free_area_pmd(dir, address, end - address);
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	flush_tlb_all();
}


/*
 * Careful!
 *
 * This has to add the process to the _end_ of the 
 * run-queue, not the beginning. The goodness value will
 * determine whether this process will run next. This is
 * important to get SCHED_FIFO and SCHED_RR right, where
 * a process that is either pre-empted or its time slice
 * has expired, should be moved to the tail of the run 
 * queue for its priority - Bhavesh Davda
 */
static LIST_HEAD(runqueue_head);
int nr_running;
static inline void add_to_runqueue(struct task_struct * p)
{
	list_add_tail(&p->run_list, &runqueue_head);
	nr_running++;
}
/*
 * Wake up a process. Put it on the run-queue if it's not
 * already there.  The "current" process is always on the
 * run-queue (except when the actual re-schedule is in
 * progress), and as such you're allowed to do the simpler
 * "current->state = TASK_RUNNING" to mark yourself runnable
 * without the overhead of this.
 */
static void reschedule_idle(struct task_struct * p)
{
	/* temp */
}
spinlock_t runqueue_lock = {0};
static inline int try_to_wake_up(struct task_struct * p, int synchronous)
{
	unsigned long flags;
	int success = 0;

	/*
	 * We want the common case fall through straight, thus the goto.
	 */
	spin_lock_irqsave(&runqueue_lock, flags);
	p->state = TASK_RUNNING;
	if (task_on_runqueue(p))
		goto out;
	add_to_runqueue(p);
	if (!synchronous || !(p->cpus_allowed & (1 << smp_processor_id())))
		reschedule_idle(p);
	success = 1;
out:
	spin_unlock_irqrestore(&runqueue_lock, flags);
	return success;
}

inline int wake_up_process(struct task_struct * p)
{
	return try_to_wake_up(p, 0);
}

static void __free_pages_ok (struct page *page, unsigned int order)
{

}
void __free_pages(struct page *page, unsigned int order)
{
	if (!PageReserved(page) && put_page_testzero(page))
	__free_pages_ok(page, order);	
}

int netlink_unicast(struct sock *ssk, struct sk_buff *skb, u32 pid, int nonblock)
{
	return 1;
}

/*
 *	Find the first device with a given source address.
 */
struct fib_table *local_table;

struct net_device * ip_dev_find(u32 addr)
{
	struct rt_key key;
	struct fib_result res;
	struct net_device *dev = NULL;

	memset(&key, 0, sizeof(key));
	key.dst = addr;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif

	if (!local_table || local_table->tb_lookup(local_table, &key, &res)) {
		return NULL;
	}
	if (res.type != RTN_LOCAL)
		goto out;
	dev = FIB_RES_DEV(res);
	if (dev)
		atomic_inc(&dev->refcnt);

out:
	fib_res_put(&res);
	return dev;
}
struct sk_buff *pskb_copy(struct sk_buff *skb, int gfp_mask)
{
	return NULL;
}

struct sk_buff *skb_clone(struct sk_buff *skb, int gfp_mask)
{
		return NULL;
}
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, int gfp_mask)
{
	return 0;
}

struct sk_buff *
skb_realloc_headroom(struct sk_buff *skb, unsigned int headroom)
{
	struct sk_buff *skb2;
	int delta = headroom - skb_headroom(skb);

	if (delta <= 0)
		return pskb_copy(skb, GFP_ATOMIC);

	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (skb2 == NULL ||
	    !pskb_expand_head(skb2, SKB_DATA_ALIGN(delta), 0, GFP_ATOMIC))
		return skb2;

	kfree_skb(skb2);
	return NULL;
}

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 */
void * kmem_cache_alloc (kmem_cache_t *cachep, int flags)
{
	
}

/**
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @offset: The offset to use within the page.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 * @dtor: A destructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache
 * and the @dtor is run before the pages are handed back.
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_NO_REAP - Don't automatically reap this cache when we're under
 * memory pressure.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */
kmem_cache_t *
kmem_cache_create (const char *name, size_t size, size_t offset,
	unsigned long flags, void (*ctor)(void*, kmem_cache_t *, unsigned long),
	void (*dtor)(void*, kmem_cache_t *, unsigned long))
{
	return NULL;

}

/**
 *	skb_copy_expand	-	copy and expand sk_buff
 *	@skb: buffer to copy
 *	@newheadroom: new free bytes at head
 *	@newtailroom: new free bytes at tail
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data and while doing so 
 *	allocate additional space.
 *
 *	This is used when the caller wishes to modify the data and needs a 
 *	private copy of the data to alter as well as more space for new fields.
 *	Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	You must pass %GFP_ATOMIC as the allocation priority if this function
 *	is called from an interrupt.
 */

struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				int newheadroom,
				int newtailroom,
				int gfp_mask)
{
	struct sk_buff *n;

	/*
	 *	Allocate the copy buffer
	 */
 	 
	n=alloc_skb(newheadroom + skb->len + newtailroom,
		    gfp_mask);
	if(n==NULL)
		return NULL;

	skb_reserve(n,newheadroom);

	/* Set the tail pointer and length */
	skb_put(n,skb->len);

	/* Copy the data only. */
	if (skb_copy_bits(skb, 0, n->data, skb->len))
		BUG();

	copy_skb_header(n, skb);
	return n;
}

/* Checksum skb data. */

unsigned int skb_checksum(const struct sk_buff *skb, int offset, int len, unsigned int csum)
{
	int i, copy;
	int start = skb->len - skb->data_len;
	int pos = 0;

	/* Checksum header. */
	if ((copy = start-offset) > 0) {
		if (copy > len)
			copy = len;
		csum = csum_partial(skb->data+offset, copy, csum);
		if ((len -= copy) == 0)
			return csum;
		offset += copy;
		pos = copy;
	}

	for (i=0; i<skb_shinfo(skb)->nr_frags; i++) {
		int end;

	//	BUG_TRAP(start <= offset+len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end-offset) > 0) {
			unsigned int csum2;
			u8 *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			vaddr = kmap_skb_frag(frag);
			csum2 = csum_partial(vaddr + frag->page_offset +
					     offset-start, copy, 0);
			kunmap_skb_frag(vaddr);
			csum = csum_block_add(csum, csum2, pos);
			if (!(len -= copy))
				return csum;
			offset += copy;
			pos += copy;
		}
		start = end;
	}

	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *list;

		for (list = skb_shinfo(skb)->frag_list; list; list=list->next) {
			int end;

//			BUG_TRAP(start <= offset+len);

			end = start + list->len;
			if ((copy = end-offset) > 0) {
				unsigned int csum2;
				if (copy > len)
					copy = len;
				csum2 = skb_checksum(list, offset-start, copy, 0);
				csum = csum_block_add(csum, csum2, pos);
				if ((len -= copy) == 0)
					return csum;
				offset += copy;
				pos += copy;
			}
			start = end;
		}
	}
	if (len == 0)
		return csum;

	BUG();
	return csum;
}

/* Calculate csum in the case, when packet is misrouted.
 * If it failed by some reason, ignore and send skb with wrong
 * checksum.
 */
struct sk_buff * skb_checksum_help(struct sk_buff *skb)
{
	int offset;
	unsigned int csum;

	offset = skb->h.raw - skb->data;
	if (offset > (int)skb->len)
		BUG();
	csum = skb_checksum(skb, offset, skb->len-offset, 0);

	offset = skb->tail - skb->h.raw;
	if (offset <= 0)
		BUG();
	if (skb->csum+2 > offset)
		BUG();

	*(u16*)(skb->h.raw + skb->csum) = csum_fold(csum);
	skb->ip_summed = CHECKSUM_NONE;
	return skb;
}

/* Release a nexthop info record */
#define for_fib_info() { struct fib_info *fi; \
	for (fi = fib_info_list; fi; fi = fi->fib_next)

#define endfor_fib_info() }

#ifdef CONFIG_IP_ROUTE_MULTIPATH

static spinlock_t fib_multipath_lock = SPIN_LOCK_UNLOCKED;

#define for_nexthops(fi) { int nhsel; const struct fib_nh * nh; \
for (nhsel=0, nh = (fi)->fib_nh; nhsel < (fi)->fib_nhs; nh++, nhsel++)

#define change_nexthops(fi) { int nhsel; struct fib_nh * nh; \
for (nhsel=0, nh = (struct fib_nh*)((fi)->fib_nh); nhsel < (fi)->fib_nhs; nh++, nhsel++)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

/* Hope, that gcc will optimize it to get rid of dummy loop */

#define for_nexthops(fi) { int nhsel=0; const struct fib_nh * nh = (fi)->fib_nh; \
for (nhsel=0; nhsel < 1; nhsel++)

#define change_nexthops(fi) { int nhsel=0; struct fib_nh * nh = (struct fib_nh*)((fi)->fib_nh); \
for (nhsel=0; nhsel < 1; nhsel++)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define endfor_nexthops(fi) }

int fib_info_cnt;

void free_fib_info(struct fib_info *fi)
{
	if (fi->fib_dead == 0) {
//	printk("Freeing alive fib_info %p\n", fi);
	return;
	}
	change_nexthops(fi) {
		if (nh->nh_dev)
			dev_put(nh->nh_dev);
		nh->nh_dev = NULL;
	} endfor_nexthops(fi);
	fib_info_cnt--;
	kfree(fi);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 *
 *	Yes this is inefficient, feel free to submit a quicker one.
 */

int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len; 
	int offset;
	int not_last_frag;
	struct rtable *rt = (struct rtable*)skb->dst;
	int err = 0;

	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = skb->nh.iph;

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	left = skb->len - hlen;		/* Space per frame */
	mtu = rt->u.dst.pmtu - hlen;	/* Size of data space */
	ptr = raw + hlen;		/* Where to start from */

	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while(left > 0)	{
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */

		if ((skb2 = alloc_skb(len+hlen+dev->hard_header_len+15,GFP_ATOMIC)) == NULL) {
	//		NETDEBUG(printk(KERN_INFO "IP: frag: no memory for new fragment!\n"));
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */

		skb2->pkt_type = skb->pkt_type;
		skb2->priority = skb->priority;
		skb_reserve(skb2, (dev->hard_header_len+15)&~15);
		skb_put(skb2, len + hlen);
		skb2->nh.raw = skb2->data;
		skb2->h.raw = skb2->data + hlen;
		skb2->protocol = skb->protocol;
		skb2->security = skb->security;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		skb2->dst = dst_clone(skb->dst);
		skb2->dev = skb->dev;

		/*
		 *	Copy the packet header into the new buffer.
		 */

		memcpy(skb2->nh.raw, skb->data, hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		if (skb_copy_bits(skb, ptr, skb2->h.raw, len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = skb2->nh.iph;
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		if (offset == 0)
			ip_options_fragment(skb);

		/* Copy the flags to each fragment. */
		IPCB(skb2)->flags = IPCB(skb)->flags;

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		ptr += len;
		offset += len;

#ifdef CONFIG_NET_SCHED
		skb2->tc_index = skb->tc_index;
#endif
#ifdef CONFIG_NETFILTER
		skb2->nfmark = skb->nfmark;
		/* Connection association is same as pre-frag packet */
		skb2->nfct = skb->nfct;
		nf_conntrack_get(skb2->nfct);
#ifdef CONFIG_NETFILTER_DEBUG
		skb2->nf_debug = skb->nf_debug;
#endif
#endif

		/*
		 *	Put this fragment into the sending queue.
		 */

		IP_INC_STATS(IpFragCreates);

		iph->tot_len = htons(len + hlen);

		ip_send_check(iph);

		err = output(skb2);
		if (err)
			goto fail;
	}
	kfree_skb(skb);
	IP_INC_STATS(IpFragOKs);
	return err;

fail:
	kfree_skb(skb); 
	IP_INC_STATS(IpFragFails);
	return err;
}