#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/seq_file.h>

#include "lve_internal.h"
#include "lve_debug.h"
#include "lve_callchain.h"

struct port_entry {
	/* tcp has 0 .. 65k port id */
	unsigned short	pe_port;
	bool		pe_permit;
	struct list_head pe_link;
};

void lve_net_port_show(struct seq_file *m, struct light_ve *lve)
{
	struct list_head *pos;
	struct port_entry *pe;

	seq_printf(m, "ports policy: %s\n",
		    lve->lve_net.ln_port_policy ? "enable" : "disable" );
	seq_printf(m, "ports ACL:");

	read_lock(&lve->lve_net.ln_port_lock);
	list_for_each(pos, &lve->lve_net.ln_port_list) {
		pe = list_entry(pos, struct port_entry, pe_link);
		seq_printf(m, "%hu %s:", pe->pe_port, pe->pe_permit ? "yes" : "no");

	}
	read_unlock(&lve->lve_net.ln_port_lock);
	seq_printf(m, "\n");
}

static struct kmem_cache *lve_port_cachep;

static struct port_entry *alloc_port_entry(unsigned long port, bool permit)
{
	struct port_entry *port_entry;

	port_entry = kmem_cache_zalloc(lve_port_cachep, GFP_KERNEL);
	if (port_entry == NULL) {
		LVE_ERR("can't allocate port_entry\n");
		return NULL;
	}

	port_entry->pe_port = port;
	port_entry->pe_permit = permit;
	INIT_LIST_HEAD(&port_entry->pe_link);

	return port_entry;
}

/* we expect to have few entry per lve so list is good enough
 * if we will have more than 10-20 entries we will replace with tree 
 */
static struct port_entry *find_port_entry(struct lve_net *net,
					  unsigned port)
{
	struct list_head *pos;
	struct port_entry *pe;

	pos = &net->ln_port_list;
	list_for_each(pos, &net->ln_port_list) {
		pe = list_entry(pos, struct port_entry, pe_link);
		if (pe->pe_port >= port) {
			LVE_DBG("found pe %u %s\n", pe->pe_port,
				pe->pe_permit ? "yes" : "no");
			return pe;
		}
	}
	return NULL;
}

static int add_or_update_port_entry(struct lve_net *net,
				    struct port_entry *port_entry)
{
	struct port_entry *tmp = NULL;
	int ret;

	write_lock(&net->ln_port_lock);
	tmp = find_port_entry(net, port_entry->pe_port);
	if ((tmp == NULL) || (tmp->pe_port > port_entry->pe_port)) {
		LVE_DBG("add port %u - %u\n", 
			port_entry->pe_port, port_entry->pe_permit);
		list_add_tail(&port_entry->pe_link,
			 tmp == NULL ? &net->ln_port_list : &tmp->pe_link);
		ret = 0;
	} else {
		LVE_DBG("port=%u entry exists, update it\n", tmp->pe_port);
		tmp->pe_permit = port_entry->pe_permit;
		ret = -EALREADY;
	}
	write_unlock(&net->ln_port_lock);

	return ret;
}

int lve_net_port_init(struct light_ve *lve)
{
	LVE_ENTER("lve %p\n", lve);

	INIT_LIST_HEAD(&lve->lve_net.ln_port_list);
	rwlock_init(&lve->lve_net.ln_port_lock);
	/* checks disabled - always allow */
	lve->lve_net.ln_port_policy = false;

	return 0;
}

void lve_net_port_fini(struct light_ve *lve)
{
	struct port_entry *pe, *next;
	LVE_ENTER("lve %p\n", lve);
	/* flush */
	list_for_each_entry_safe(pe, next, &lve->lve_net.ln_port_list, pe_link)
		kmem_cache_free(lve_port_cachep, pe);
}

int lve_net_port_def(struct light_ve *lve, bool policy)
{
	write_lock(&lve->lve_net.ln_port_lock);
	lve->lve_net.ln_port_policy = policy;
	write_unlock(&lve->lve_net.ln_port_lock);

	return 0;
}

int lve_net_port_add(struct light_ve *lve, unsigned port, bool policy)
{
	struct port_entry *pe;

	if (port == 0)
		return -EINVAL;

	pe = alloc_port_entry(port, policy);
	if (add_or_update_port_entry(&lve->lve_net, pe) == -EALREADY)
		kmem_cache_free(lve_port_cachep, pe);

	return 0;
}

int lve_net_port_del(struct light_ve *lve, unsigned port)
{
	struct lve_net *net = &lve->lve_net;
	struct port_entry *tmp;
	int ret = 0;
	bool todel;

	if (port == 0)
		return -EINVAL;

	write_lock(&net->ln_port_lock);
	tmp = find_port_entry(net, port);
	todel = (tmp != NULL && tmp->pe_port == port);
	if (todel)
		list_del(&tmp->pe_link);
	write_unlock(&net->ln_port_lock);

	if (todel)
		kmem_cache_free(lve_port_cachep, tmp);
	else
		ret = -ESRCH;

	return ret;
}

static int lve_net_bind_perm(void *arg)
{
	int ret = 0;
	struct switch_data *sw_data;
	struct lve_net *net;
	struct sockaddr_in *port;
	unsigned snum;
	struct port_entry *port_entry;

	sw_data = LVE_TAG_GET(current);
	/* we are not in lve - ignore checks */
	if (sw_data == NULL)
		return 0;

	BUG_ON(sw_data->sw_from == NULL);
	net = &sw_data->sw_from->lve_net;

	port = (struct sockaddr_in *)arg;
	snum = ntohs(port->sin_port);

	read_lock(&net->ln_port_lock);
	/* disabled -> skip */
	if (!net->ln_port_policy)
		goto out;

	port_entry = find_port_entry(net, snum);
	if (port_entry == NULL) {
		LVE_DBG("lve %x can't find entry port=%u\n", sw_data->sw_from->lve_id, snum);
		ret = -EACCES;
		goto out;
	}

	ret = !port_entry->pe_permit ? -EACCES : 0;
out:
	read_unlock(&net->ln_port_lock);
	LVE_DBG("LVE %x  bind to port=%u, ret=%d\n", sw_data->sw_from->lve_id, snum, ret);
	LVE_TAG_PUT(sw_data);

	return ret;
}

static struct lve_call *bind_cb;

int __init lve_network_port_init(void)
{
	int rc = 0;

	lve_port_cachep = kmem_cache_create("lve_port_cache",
				sizeof(struct port_entry),
				0, 0, NULL);
	if (lve_port_cachep == NULL) {
		LVE_ERR("Can't create cache lve_port_cache\n");
		return -ENOMEM;
	}

	bind_cb = lve_callchain_register(LVE_BIND, lve_net_bind_perm);
	if (IS_ERR(bind_cb)) {
		rc = PTR_ERR(bind_cb);
		bind_cb = NULL;
	}

	if (rc == -ENOSYS) {
		LVE_WARN("LVE_BIND callback isn't implemented\n");
		rc = 0;
	}

	if (rc < 0)
		kmem_cache_destroy(lve_port_cachep);

	return rc;
}

void lve_network_port_fini(void)
{
	lve_callchain_unregister(bind_cb);

	kmem_cache_destroy(lve_port_cachep);
}
