#include <doca_argp.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include "random_spi_gw.h"

DOCA_LOG_REGISTER(RANDOM_SPI_GW_ARGP);

const uint32_t MAX_NUM_SPI = 64*1024;

static doca_error_t
dmac_callback(void *param, void *config_voidp)
{
	struct random_spi_gw_config * config = config_voidp;
	const char *param_str = param;

	rte_ether_unformat_addr(param_str, &config->encap_hdr.eth.dst_addr);
	DOCA_LOG_INFO("Selected dmac: %s", param_str);
	return DOCA_SUCCESS;
}

static doca_error_t
num_spi_callback(void *param, void *config_voidp)
{
	struct random_spi_gw_config * config = config_voidp;
	const uint32_t *param_int = param;

    if (*param_int > MAX_NUM_SPI) {
        DOCA_LOG_ERR("Invalid num_spi; max: %d; using %d", MAX_NUM_SPI, config->num_spi);
        return DOCA_ERROR_INVALID_VALUE;
    }

	config->num_spi = *param_int;
	DOCA_LOG_INFO("Selected %d SPIs", config->num_spi);
	return DOCA_SUCCESS;
}


doca_error_t
random_spi_gw_register_argp_params(void)
{
	struct doca_argp_param * param = NULL;
    doca_error_t ret = DOCA_SUCCESS;

	ret = doca_argp_param_create(&param);
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
	
	ret = doca_argp_param_create(&param);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(ret));
        return ret;
    }
    doca_argp_param_set_short_name(param, "n");
	doca_argp_param_set_long_name(param, "num_spi");
	doca_argp_param_set_description(param, "Number of SPIs across which to spread traffic");
	doca_argp_param_set_callback(param, num_spi_callback);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_INT);
	ret = doca_argp_register_param(param);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(ret));
        return ret;
    }
	
    return DOCA_SUCCESS;
}
