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
#include "../include/linux/stat.h"
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

	if (net_ratelimit())
//		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
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
void __kfree_skb(struct sk_buff *skb)
{
	if (skb->list) {
	 	printk(KERN_WARNING "Warning: kfree_skb passed an skb still "
		       "on a list (from %p).\n", NET_CALLER(skb));
		BUG();
	}

	dst_release(skb->dst);
	if(skb->destructor) {
		if (in_irq()) {
			printk(KERN_WARNING "Warning: kfree_skb on hard IRQ %p\n",
				NET_CALLER(skb));
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
