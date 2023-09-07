#include <doca_argp.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include "random_spi_gw.h"

DOCA_LOG_REGISTER(RANDOM_SPI_GW_ARGP);

static doca_error_t
dmac_callback(void *param, void *config_voidp)
{
	struct random_spi_gw_config * config = config_voidp;
	const char *param_str = param;

	rte_ether_unformat_addr(param_str, &config->encap_hdr.eth.dst_addr);
	DOCA_LOG_INFO("Selected dmac: %s", param_str);
	return DOCA_SUCCESS;
}


doca_error_t
random_spi_gw_register_argp_params(void)
{
	struct doca_argp_param * param = NULL;
	int ret = doca_argp_param_create(&param);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(ret));
        return ret;
    }
	doca_argp_param_set_short_name(param, "d");
	doca_argp_param_set_long_name(param, "dmac");
	doca_argp_param_set_description(param, "Encap destination mac addr");
	doca_argp_param_set_callback(param, dmac_callback);
	doca_argp_param_set_mandatory(param);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_STRING);
	ret = doca_argp_register_param(param);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(ret));
        return ret;
    }
	
    return DOCA_SUCCESS;
}
