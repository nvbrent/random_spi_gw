/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <doca_dpdk.h>
#include <doca_log.h>

#include <samples/common.h>

#include <random_spi_gw.h>


DOCA_LOG_REGISTER(RANDOM_SPI_GW_DEV);

#define DEFAULT_NB_CORES 4		/* Default number of running cores */
#define WINDOW_SIZE 64			/* The size of the replay window */

#define KEY_LEN_BITS 256
#define KEY_LEN_BYTES (KEY_LEN_BITS / 8)

#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define TIMEOUT_USEC (10 * 1000) // timeout process-entries after 10 millisec

typedef doca_error_t (*jobs_check)(struct doca_devinfo *);

/**
 * Check if given device is capable of executing a DOCA_IPSEC_JOB_SA_CREATE job.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports DOCA_IPSEC_JOB_SA_CREATE and DOCA_ERROR otherwise.
 */
static doca_error_t
job_ipsec_create_is_supported(struct doca_devinfo *devinfo)
{
	doca_error_t result;

	result = doca_ipsec_job_get_supported(devinfo, DOCA_IPSEC_JOB_SA_CREATE);
	if (result != DOCA_SUCCESS)
		return result;
	result = doca_ipsec_sequence_number_get_supported(devinfo);
	if (result != DOCA_SUCCESS)
		return result;
	return doca_ipsec_antireplay_get_supported(devinfo);
}


/*
 * Initialized DOCA workq with ipsec context
 *
 * @dev [in]: doca device to connect to context
 * @ctx [in]: ipsec context
 * @workq [out]: created workq
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
random_spi_gw_init_workq(struct doca_dev *dev, struct doca_ctx *ctx, struct doca_workq **workq)
{
	doca_error_t result;

	result = doca_ctx_dev_add(ctx, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register device with lib context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_start(ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start lib context: %s", doca_get_error_string(result));
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}

	result = doca_workq_create(1, workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		doca_ctx_stop(ctx);
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}

	result = doca_ctx_workq_add(ctx, *workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register work queue with context: %s", doca_get_error_string(result));
		doca_workq_destroy(*workq);
		doca_ctx_stop(ctx);
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}
	return DOCA_SUCCESS;
}

doca_error_t
random_spi_gw_ipsec_ctx_create(struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = doca_ipsec_create(&app_cfg->ipsec_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create IPSEC context: %s", doca_get_error_string(result));
		return result;
	}

	app_cfg->doca_ctx = doca_ipsec_as_ctx(app_cfg->ipsec_ctx);

	result = random_spi_gw_init_workq(app_cfg->pf.dev, app_cfg->doca_ctx, &app_cfg->doca_workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to initialize DOCA workq: %s", doca_get_error_string(result));
		doca_ipsec_destroy(app_cfg->ipsec_ctx);
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Destroy DOCA workq and stop doca context
 *
 * @dev [in]: doca device to connect to context
 * @ctx [in]: ipsec context
 * @workq [in]: doca workq
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
random_spi_gw_destroy_workq(struct doca_dev *dev, struct doca_ctx *ctx, struct doca_workq *workq)
{
	doca_error_t tmp_result, result = DOCA_SUCCESS;

	tmp_result = doca_ctx_workq_rm(ctx, workq);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove work queue from ctx: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_ctx_stop(ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to stop context: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_workq_destroy(workq);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy work queue: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_ctx_dev_rm(ctx, dev);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove device from ctx: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
random_spi_gw_ipsec_ctx_destroy(const struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = random_spi_gw_destroy_workq(app_cfg->pf.dev, app_cfg->doca_ctx, app_cfg->doca_workq);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy context resources: %s", doca_get_error_string(result));

	result = doca_ipsec_destroy(app_cfg->ipsec_ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy IPSec library context: %s", doca_get_error_string(result));

	result = doca_dev_close(app_cfg->pf.dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy secured DOCA dev: %s", doca_get_error_string(result));

	return result;
}


doca_error_t
random_spi_gw_destroy_ipsec_sa(struct random_spi_gw_config *app_cfg, struct doca_ipsec_sa *sa)
{
	if (!sa) {
		return DOCA_SUCCESS;
	}

	struct doca_event event = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;

	const struct doca_ipsec_sa_destroy_job sa_destroy = {
		.base = (struct doca_job) {
			.type = DOCA_IPSEC_JOB_SA_DESTROY,
			.flags = DOCA_JOB_FLAGS_NONE,
			.ctx = app_cfg->doca_ctx,
		},
		.sa = sa,
	};

	/* Enqueue IPsec job */
	result = doca_workq_submit(app_cfg->doca_workq, &sa_destroy.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit ipsec job: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait for job completion */
	while ((result = doca_workq_progress_retrieve(app_cfg->doca_workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to retrieve job: %s", doca_get_error_string(result));

	return result;
}

void
random_spi_gw_destroy_sas(struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;
	struct doca_ipsec_sa *sa;

	for (int i = 0; i < app_cfg->num_spi; i++) {
		sa = app_cfg->connections[i].encrypt_sa;
		result = random_spi_gw_destroy_ipsec_sa(app_cfg, sa);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy the SA for encrypt rule with index [%d]", i);

		sa = app_cfg->connections[i].decrypt_sa;
		result = random_spi_gw_destroy_ipsec_sa(app_cfg, sa);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy the SA for encrypt rule with index [%d]", i);
	}
}



doca_error_t
random_spi_gw_init_devices(struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = open_doca_device_with_pci(app_cfg->pf.dev_pci_dbdf, job_ipsec_create_is_supported, &app_cfg->pf.dev);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for the secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dpdk_port_probe(app_cfg->pf.dev, "dv_flow_en=2,dv_xmeta_en=4,fdb_def_rule_en=0,representor=vf[0]");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}
