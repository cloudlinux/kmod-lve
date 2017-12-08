#ifndef _LVE_NET_H_
#define _LVE_NET_H_

struct light_ve;

struct lve_net_stats {
	atomic64_t out_limit;
	atomic64_t out_total;
	atomic64_t in_limit;
	atomic64_t in_total;
};

struct lve_net {
	struct lve_net_stats	ln_stats;
	/* port access limitation */
	/* global policy - true = need a check tree, 
	 * false = always allow */
	bool			ln_port_policy;
	rwlock_t		ln_port_lock;
	struct list_head	ln_port_list;
	/* port access limitation end */
};


int lve_net_port_def(struct light_ve *lve, bool policy);
int lve_net_port_add(struct light_ve *lve, unsigned port, bool policy);
int lve_net_port_del(struct light_ve *lve, unsigned port);
void lve_net_port_show(struct seq_file *m, struct light_ve *lve);

void lve_net_traf_show(struct seq_file *m, struct light_ve *lve);
int lve_net_bw_limit_set(struct light_ve *lve, uint64_t bw_in, uint64_t bw_out);

/* per lve_init */
int lve_net_port_init(struct light_ve *lve);
void lve_net_port_fini(struct light_ve *lve);

int lve_net_init(struct light_ve *lve);
void lve_net_fini(struct light_ve *lve);

/* global init */
int __init lve_network_init(void);
void lve_network_fini(void);

int __init lve_network_traf_init(void);
void lve_network_traf_fini(void);

int __init lve_network_port_init(void);
void lve_network_port_fini(void);

#endif /* _LVE_NET_H_ */
