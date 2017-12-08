#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>

#include "lve_internal.h"
#include "lve_debug.h"
#include "lve_net.h"
#include "tags.h"
#include "lve_kmod_c.h"
#include "lve_callchain.h"

#define IN	true
#define OUT	false

void lve_net_traf_show(struct seq_file *m, struct light_ve *lve)
{
	seq_printf(m, "%25llu%25llu%25llu%25llu",
		(uint64_t)atomic64_read(&lve->lve_net.ln_stats.out_limit),
		(uint64_t)atomic64_read(&lve->lve_net.ln_stats.in_limit),
		(uint64_t)atomic64_read(&lve->lve_net.ln_stats.out_total),
		(uint64_t)atomic64_read(&lve->lve_net.ln_stats.in_total));
}

int lve_net_bw_limit_set(struct light_ve *lve, uint64_t bw_in, uint64_t bw_out)
{
	atomic64_set(&lve->lve_net.ln_stats.in_limit, bw_in);
	atomic64_set(&lve->lve_net.ln_stats.out_limit, bw_out);

	/* todo apply limits */

	return 0;
}

#ifdef HAVE_LVE_TRAF_CONTROL
static int lve_mark_out_packets(void *arg)
{
	struct sk_buff *skb;
	struct switch_data *sw_data;
	struct light_ve *ve;

	skb = (struct sk_buff *)arg;
	if (!skb)
		goto out;

	sw_data = LVE_TAG_GET(current);
	if (sw_data == NULL)
		goto out;

	LVE_DBG("sw_data=%p, comm=%s, actual data len=%u, data len=%u, mark=%u\n",
		sw_data, current->comm, skb->len, skb->data_len, skb->mark);
	ve = sw_data->sw_from;
	BUG_ON(!ve);
	skb->mark = (uint32_t)ve->lve_id;
	LVE_DBG("packet marker=%u\n", skb->mark);
	LVE_TAG_PUT(sw_data);
out:
	return 0;
}

static int lve_account_packets(void *arg, bool direction)
{
	uint64_t size = (uintptr_t)arg;
	struct switch_data *sw_data;
	struct light_ve *ve;

	sw_data = LVE_TAG_GET(current);
	if (sw_data == NULL)
		goto out;

	ve = sw_data->sw_from;
	BUG_ON(!ve);
	if (direction == IN) {
		atomic64_add(size, &ve->lve_net.ln_stats.in_total);
		LVE_DBG("%s: received data size=%llu, total=%llu\n", current->comm, size,
			(uint64_t)atomic64_read(&ve->lve_net.ln_stats.in_total));
	} else {
		atomic64_add(size, &ve->lve_net.ln_stats.out_total);
		LVE_DBG("%s: received data size=%llu, total=%llu\n", current->comm, size,
			(uint64_t)atomic64_read(&ve->lve_net.ln_stats.out_total));
	}
	LVE_TAG_PUT(sw_data);
out:
	return 0;
}

static int lve_acc_packets_in(void *arg)
{
	return lve_account_packets(arg, IN);
}

static int lve_acc_packets_out(void *arg)
{
	return lve_account_packets(arg, OUT);
}
#endif

struct lve_traf_event_cback {
	enum lve_event ev;
	lve_callback cb;
	struct lve_call *call;
};

static struct lve_traf_event_cback lve_traf_cb[] = {
#ifdef HAVE_LVE_TRAF_CONTROL
	{LVE_TRAF_MARK_OUT, lve_mark_out_packets, NULL},
	{LVE_TRAF_ACCOUNT_IN, lve_acc_packets_in, NULL},
	{LVE_TRAF_ACCOUNT_OUT, lve_acc_packets_out, NULL},
#endif
	{0, NULL, NULL} /* terminator */
};

int __init lve_network_traf_init(void)
{
	int rc = 0, i;

	for (i = 0; lve_traf_cb[i].cb; i++) {
		struct lve_call **call =  &lve_traf_cb[i].call;
		enum lve_event ev =  lve_traf_cb[i].ev;

		*call  = lve_callchain_register(ev, lve_traf_cb[i].cb);
		if (IS_ERR(*call)) {
			rc = PTR_ERR(*call);
			*call = NULL;
		}

		if (rc == -ENOSYS) {
			LVE_WARN("%d callback isn't implemented\n", ev);
			rc = 0;
		}

		if (rc < 0) {
			LVE_ERR("Cannot register net traf callback, event type = %d\n", ev);
			break;
		}
	}

	return rc;
}

void lve_network_traf_fini(void)
{
	int i;

	for (i = 0; lve_traf_cb[i].cb; i++)
		lve_callchain_unregister(lve_traf_cb[i].call);
}
