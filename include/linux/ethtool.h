/*
 * ethtool.h: Defines for Linux ethtool.
 *
 * Copyright (C) 1998 David S. Miller (davem@redhat.com)
 * Copyright 2001 Jeff Garzik <jgarzik@mandrakesoft.com>
 * Portions Copyright 2001 Sun Microsystems (thockin@sun.com)
 * Portions Copyright 2002 Intel (eli.kupermann@intel.com,
 *                                christopher.leech@intel.com,
 *                                scott.feldman@intel.com)
 */

#ifndef _LINUX_ETHTOOL_H
#define _LINUX_ETHTOOL_H


/* This should work for both 32 and 64 bit userland. */
struct ethtool_cmd {
	unsigned int	cmd;
	unsigned int	supported;	/* Features this interface supports */
	unsigned int	advertising;	/* Features this interface advertises */
	unsigned short	speed;		/* The forced speed, 10Mb, 100Mb, gigabit */
	unsigned char	duplex;		/* Duplex, half or full */
	unsigned char	port;		/* Which connector port */
	unsigned char	phy_address;
	unsigned char	transceiver;	/* Which tranceiver to use */
	unsigned char	autoneg;	/* Enable or disable autonegotiation */
	unsigned int	maxtxpkt;	/* Tx pkts before generating tx int */
	unsigned int	maxrxpkt;	/* Rx pkts before generating rx int */
	unsigned int	reserved[4];
};

#define ETHTOOL_BUSINFO_LEN	32
/* these strings are set to whatever the driver author decides... */
struct ethtool_drvinfo {
	unsigned int	cmd;
	char	driver[32];	/* driver short name, "tulip", "eepro100" */
	char	version[32];	/* driver version string */
	char	fw_version[32];	/* firmware version string, if applicable */
	char	bus_info[ETHTOOL_BUSINFO_LEN];	/* Bus info for this IF. */
				/* For PCI devices, use pci_dev->slot_name. */
	char	reserved1[32];
	char	reserved2[16];
	unsigned int	n_stats;	/* number of u64's from ETHTOOL_GSTATS */
	unsigned int	testinfo_len;
	unsigned int	eedump_len;	/* Size of data from ETHTOOL_GEEPROM (bytes) */
	unsigned int	regdump_len;	/* Size of data from ETHTOOL_GREGS (bytes) */
};

#define SOPASS_MAX	6
/* wake-on-lan settings */
struct ethtool_wolinfo {
	unsigned int	cmd;
	unsigned int	supported;
	unsigned int	wolopts;
	unsigned char	sopass[SOPASS_MAX]; /* SecureOn(tm) password */
};

/* for passing single values */
struct ethtool_value {
	unsigned int	cmd;
	unsigned int	data;
};

/* for passing big chunks of data */
struct ethtool_regs {
	unsigned int	cmd;
	unsigned int	version; /* driver-specific, indicates different chips/revs */
	unsigned int	len; /* bytes */
	unsigned char	data[0];
};

/* for passing EEPROM chunks */
struct ethtool_eeprom {
	unsigned int	cmd;
	unsigned int	magic;
	unsigned int	offset; /* in bytes */
	unsigned int	len; /* in bytes */
	unsigned char	data[0];
};

/* for configuring coalescing parameters of chip */
struct ethtool_coalesce {
	unsigned int	cmd;	/* ETHTOOL_{G,S}COALESCE */

	/* How many usecs to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_max_coalesced_frames
	 * is used.
	 */
	unsigned int	rx_coalesce_usecs;

	/* How many packets to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause RX interrupts to never be
	 * generated.
	 */
	unsigned int	rx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being services by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	unsigned int	rx_coalesce_usecs_irq;
	unsigned int	rx_max_coalesced_frames_irq;

	/* How many usecs to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_max_coalesced_frames
	 * is used.
	 */
	unsigned int	tx_coalesce_usecs;

	/* How many packets to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause TX interrupts to never be
	 * generated.
	 */
	unsigned int	tx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being services by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	unsigned int	tx_coalesce_usecs_irq;
	unsigned int	tx_max_coalesced_frames_irq;

	/* How many usecs to delay in-memory statistics
	 * block updates.  Some drivers do not have an in-memory
	 * statistic block, and in such cases this value is ignored.
	 * This value must not be zero.
	 */
	unsigned int	stats_block_coalesce_usecs;

	/* Adaptive RX/TX coalescing is an algorithm implemented by
	 * some drivers to improve latency under low packet rates and
	 * improve throughput under high packet rates.  Some drivers
	 * only implement one of RX or TX adaptive coalescing.  Anything
	 * not implemented by the driver causes these values to be
	 * silently ignored.
	 */
	unsigned int	use_adaptive_rx_coalesce;
	unsigned int	use_adaptive_tx_coalesce;

	/* When the packet rate (measured in packets per second)
	 * is below pkt_rate_low, the {rx,tx}_*_low parameters are
	 * used.
	 */
	unsigned int	pkt_rate_low;
	unsigned int	rx_coalesce_usecs_low;
	unsigned int	rx_max_coalesced_frames_low;
	unsigned int	tx_coalesce_usecs_low;
	unsigned int	tx_max_coalesced_frames_low;

	/* When the packet rate is below pkt_rate_high but above
	 * pkt_rate_low (both measured in packets per second) the
	 * normal {rx,tx}_* coalescing parameters are used.
	 */

	/* When the packet rate is (measured in packets per second)
	 * is above pkt_rate_high, the {rx,tx}_*_high parameters are
	 * used.
	 */
	unsigned int	pkt_rate_high;
	unsigned int	rx_coalesce_usecs_high;
	unsigned int	rx_max_coalesced_frames_high;
	unsigned int	tx_coalesce_usecs_high;
	unsigned int	tx_max_coalesced_frames_high;

	/* How often to do adaptive coalescing packet rate sampling,
	 * measured in seconds.  Must not be zero.
	 */
	unsigned int	rate_sample_interval;
};

/* for configuring RX/TX ring parameters */
struct ethtool_ringparam {
	unsigned int	cmd;	/* ETHTOOL_{G,S}RINGPARAM */

	/* Read only attributes.  These indicate the maximum number
	 * of pending RX/TX ring entries the driver will allow the
	 * user to set.
	 */
	unsigned int	rx_max_pending;
	unsigned int	rx_mini_max_pending;
	unsigned int	rx_jumbo_max_pending;
	unsigned int	tx_max_pending;

	/* Values changeable by the user.  The valid values are
	 * in the range 1 to the "*_max_pending" counterpart above.
	 */
	unsigned int	rx_pending;
	unsigned int	rx_mini_pending;
	unsigned int	rx_jumbo_pending;
	unsigned int	tx_pending;
};

/* for configuring link flow control parameters */
struct ethtool_pauseparam {
	unsigned int	cmd;	/* ETHTOOL_{G,S}PAUSEPARAM */

	/* If the link is being auto-negotiated (via ethtool_cmd.autoneg
	 * being true) the user may set 'autonet' here non-zero to have the
	 * pause parameters be auto-negotiated too.  In such a case, the
	 * {rx,tx}_pause values below determine what capabilities are
	 * advertised.
	 *
	 * If 'autoneg' is zero or the link is not being auto-negotiated,
	 * then {rx,tx}_pause force the driver to use/not-use pause
	 * flow control.
	 */
	unsigned int	autoneg;
	unsigned int	rx_pause;
	unsigned int	tx_pause;
};

#define ETH_GSTRING_LEN		32
enum ethtool_stringset {
	ETH_SS_TEST		= 0,
	ETH_SS_STATS,
};

/* for passing string sets for data tagging */
struct ethtool_gstrings {
	unsigned int	cmd;		/* ETHTOOL_GSTRINGS */
	unsigned int	string_set;	/* string set id e.c. ETH_SS_TEST, etc*/
	unsigned int	len;		/* number of strings in the string set */
	unsigned char	data[0];
};

enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE	= (1 << 0),	/* online / offline */
	ETH_TEST_FL_FAILED	= (1 << 1),	/* test passed / failed */
};

/* for requesting NIC test and getting results*/
struct ethtool_test {
	unsigned int	cmd;		/* ETHTOOL_TEST */
	unsigned int	flags;		/* ETH_TEST_FL_xxx */
	unsigned int	reserved;
	unsigned int	len;		/* result length, in number of u64 elements */
	unsigned long long	data[0];
};

/* for dumping NIC-specific statistics */
struct ethtool_stats {
	unsigned int	cmd;		/* ETHTOOL_GSTATS */
	unsigned int	n_stats;	/* number of unsigned long long's being returned */
	unsigned long long	data[0];
};

/* CMDs currently supported */
#define ETHTOOL_GSET		0x00000001 /* Get settings. */
#define ETHTOOL_SSET		0x00000002 /* Set settings, privileged. */
#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_GREGS		0x00000004 /* Get NIC registers, privileged. */
#define ETHTOOL_GWOL		0x00000005 /* Get wake-on-lan options. */
#define ETHTOOL_SWOL		0x00000006 /* Set wake-on-lan options, priv. */
#define ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#define ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level, priv. */
#define ETHTOOL_NWAY_RST	0x00000009 /* Restart autonegotiation, priv. */
#define ETHTOOL_GLINK		0x0000000a /* Get link status (ethtool_value) */
#define ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#define ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data, priv. */
#define ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
#define ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config, priv. */
#define ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
#define ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters, priv. */
#define ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
#define ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters, priv. */
#define ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#define ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#define ETHTOOL_GSG		0x00000018 /* Get scatter-gather enable
					    * (ethtool_value) */
#define ETHTOOL_SSG		0x00000019 /* Set scatter-gather enable
					    * (ethtool_value), priv. */
#define ETHTOOL_TEST		0x0000001a /* execute NIC self-test, priv. */
#define ETHTOOL_GSTRINGS	0x0000001b /* get specified string set */
#define ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#define ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */

/* compatibility with older code */
#define SPARC_ETH_GSET		ETHTOOL_GSET
#define SPARC_ETH_SSET		ETHTOOL_SSET

/* Indicates what features are supported by the interface. */
#define SUPPORTED_10baseT_Half		(1 << 0)
#define SUPPORTED_10baseT_Full		(1 << 1)
#define SUPPORTED_100baseT_Half		(1 << 2)
#define SUPPORTED_100baseT_Full		(1 << 3)
#define SUPPORTED_1000baseT_Half	(1 << 4)
#define SUPPORTED_1000baseT_Full	(1 << 5)
#define SUPPORTED_Autoneg		(1 << 6)
#define SUPPORTED_TP			(1 << 7)
#define SUPPORTED_AUI			(1 << 8)
#define SUPPORTED_MII			(1 << 9)
#define SUPPORTED_FIBRE			(1 << 10)
#define SUPPORTED_BNC			(1 << 11)

/* Indicates what features are advertised by the interface. */
#define ADVERTISED_10baseT_Half		(1 << 0)
#define ADVERTISED_10baseT_Full		(1 << 1)
#define ADVERTISED_100baseT_Half	(1 << 2)
#define ADVERTISED_100baseT_Full	(1 << 3)
#define ADVERTISED_1000baseT_Half	(1 << 4)
#define ADVERTISED_1000baseT_Full	(1 << 5)
#define ADVERTISED_Autoneg		(1 << 6)
#define ADVERTISED_TP			(1 << 7)
#define ADVERTISED_AUI			(1 << 8)
#define ADVERTISED_MII			(1 << 9)
#define ADVERTISED_FIBRE		(1 << 10)
#define ADVERTISED_BNC			(1 << 11)

/* The following are all involved in forcing a particular link
 * mode for the device for setting things.  When getting the
 * devices settings, these indicate the current mode and whether
 * it was foced up into this mode or autonegotiated.
 */

/* The forced speed, 10Mb, 100Mb, gigabit. */
#define SPEED_10		10
#define SPEED_100		100
#define SPEED_1000		1000

/* Duplex, half or full. */
#define DUPLEX_HALF		0x00
#define DUPLEX_FULL		0x01

/* Which connector port. */
#define PORT_TP			0x00
#define PORT_AUI		0x01
#define PORT_MII		0x02
#define PORT_FIBRE		0x03
#define PORT_BNC		0x04

/* Which tranceiver to use. */
#define XCVR_INTERNAL		0x00
#define XCVR_EXTERNAL		0x01
#define XCVR_DUMMY1		0x02
#define XCVR_DUMMY2		0x03
#define XCVR_DUMMY3		0x04

/* Enable or disable autonegotiation.  If this is set to enable,
 * the forced link modes above are completely ignored.
 */
#define AUTONEG_DISABLE		0x00
#define AUTONEG_ENABLE		0x01

/* Wake-On-Lan options. */
#define WAKE_PHY		(1 << 0)
#define WAKE_UCAST		(1 << 1)
#define WAKE_MCAST		(1 << 2)
#define WAKE_BCAST		(1 << 3)
#define WAKE_ARP		(1 << 4)
#define WAKE_MAGIC		(1 << 5)
#define WAKE_MAGICSECURE	(1 << 6) /* only meaningful if WAKE_MAGIC */

#endif /* _LINUX_ETHTOOL_H */
