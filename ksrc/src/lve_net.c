#include <linux/kernel.h>
#include <linux/module.h>

#include "lve_internal.h"

static void lve_net_stat_init(struct light_ve *lve)
{
	memset(&lve->lve_net.ln_stats, 0, sizeof(lve->lve_net.ln_stats));
}

int lve_net_init(struct light_ve *lve)
{
	int ret;

	ret = lve_net_port_init(lve);
	if (ret < 0)
		return ret;

	lve_net_stat_init(lve);
	return 0;
}

void lve_net_fini(struct light_ve *lve)
{
	lve_net_port_fini(lve);
}

int __init lve_network_init(void)
{
	int ret;
	
	ret = lve_network_port_init();
	if (ret < 0)
		return ret;
		
	lve_network_traf_init();
	return 0;
}

void lve_network_fini(void)
{
	lve_network_port_fini();
	lve_network_traf_fini();
}
