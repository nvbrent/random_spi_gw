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
task_ipsec_create_is_supported(struct doca_devinfo *devinfo)
{
	doca_error_t result;

	result = doca_ipsec_cap_task_sa_create_is_supported(devinfo);
	if (result != DOCA_SUCCESS)
		return result;
	result = doca_ipsec_cap_task_sa_destroy_is_supported(devinfo);
	if (result != DOCA_SUCCESS)
		return result;
	result = doca_ipsec_sequence_number_get_supported(devinfo);
	if (result != DOCA_SUCCESS)
		return result;
	return doca_ipsec_antireplay_get_supported(devinfo);
}

/*
 * Callback for finishing create tasks
 *
 * @task [in]: task that has been finished
 * @task_user_data [in]: data set by the user for the task
 * @ctx_user_data [in]: data set by the user for ctx
 */
static void
create_task_completed_cb(struct doca_ipsec_task_sa_create *task, union doca_data task_user_data,
					      union doca_data ctx_user_data)
{
	DOCA_LOG_INFO("Task completed: task-%p, user_data=0x%lx, ctx_data=0x%lx", task, task_user_data.u64, ctx_user_data.u64);
}

/*
 * Callback for finishing destroy tasks
 *
 * @task [in]: task that has been finished
 * @task_user_data [in]: data set by the user for the task
 * @ctx_user_data [in]: data set by the user for ctx
 */
static void
destroy_task_completed_cb(struct doca_ipsec_task_sa_destroy *task, union doca_data task_user_data,
					      union doca_data ctx_user_data)
{
	DOCA_LOG_INFO("Task completed: task-%p, user_data=0x%lx, ctx_data=0x%lx", task, task_user_data.u64, ctx_user_data.u64);
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
random_spi_gw_init_pe(struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = doca_ipsec_task_sa_create_set_conf(app_cfg->ipsec_ctx, create_task_completed_cb, create_task_completed_cb, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set conf for sa create: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_ipsec_task_sa_destroy_set_conf(app_cfg->ipsec_ctx, destroy_task_completed_cb, destroy_task_completed_cb, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set conf for sa destroy: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_pe_create(&app_cfg->doca_pe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create pe queue: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_pe_connect_ctx(app_cfg->doca_pe, app_cfg->doca_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register pe queue with context: %s", doca_error_get_descr(result));
		doca_pe_destroy(app_cfg->doca_pe);
		return result;
	}

	result = doca_ctx_start(app_cfg->doca_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start lib context: %s", doca_error_get_descr(result));
		doca_pe_destroy(app_cfg->doca_pe);
		return result;
	}
	return DOCA_SUCCESS;
}

doca_error_t
random_spi_gw_ipsec_ctx_create(struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = doca_ipsec_create(app_cfg->pf.dev, &app_cfg->ipsec_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create IPSEC context: %s", doca_error_get_descr(result));
		return result;
	}

	if (doca_ipsec_set_sa_pool_size(app_cfg->ipsec_ctx, 4096) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set ipsec pool size");
		return false;
	}

	result = doca_ipsec_set_offload_type(app_cfg->ipsec_ctx, DOCA_IPSEC_SA_OFFLOAD_FULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set offload type: %s", doca_error_get_descr(result));
		return result;
	}

	app_cfg->doca_ctx = doca_ipsec_as_ctx(app_cfg->ipsec_ctx);

	result = random_spi_gw_init_pe(app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to initialize DOCA pe: %s", doca_error_get_descr(result));
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
random_spi_gw_destroy_pe(struct doca_ctx *ctx, struct doca_pe *pe)
{
	doca_error_t tmp_result, result = DOCA_SUCCESS;

	tmp_result = doca_ctx_stop(ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to stop context: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_pe_destroy(pe);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy pe queue: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
random_spi_gw_ipsec_ctx_destroy(const struct random_spi_gw_config *app_cfg)
{
	doca_error_t result;

	result = request_stop_ctx(app_cfg->doca_pe, app_cfg->doca_ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Unable to stop context: %s", doca_error_get_descr(result));

	result = doca_ipsec_destroy(app_cfg->ipsec_ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy IPSec library context: %s", doca_error_get_descr(result));

	result = random_spi_gw_destroy_pe(app_cfg->doca_ctx, app_cfg->doca_pe);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy context resources: %s", doca_error_get_descr(result));

	result = doca_dev_close(app_cfg->pf.dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy secured DOCA dev: %s", doca_error_get_descr(result));

	return result;
}


doca_error_t
random_spi_gw_destroy_ipsec_sa(struct random_spi_gw_config *app_cfg, struct doca_ipsec_sa *sa)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	struct doca_pe *pe = app_cfg->doca_pe;
	struct doca_ipsec *doca_ipsec_ctx = app_cfg->ipsec_ctx;
	struct doca_ipsec_task_sa_destroy *task;
	union doca_data user_data = {};
	doca_error_t result;

	result = doca_ipsec_task_sa_destroy_allocate_init(doca_ipsec_ctx, sa, user_data, &task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ipsec task: %s", doca_error_get_descr(result));
		return result;
	}

	/* Enqueue IPsec task */
	result = doca_task_submit(doca_ipsec_task_sa_destroy_as_task(task));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit ipsec task: %s", doca_error_get_descr(result));
		return result;
	}

	/* Wait for task completion */
	while (!doca_pe_progress(pe))
		nanosleep(&ts, &ts);

	if (doca_task_get_status(doca_ipsec_task_sa_destroy_as_task(task)) != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to retrieve task: %s", doca_error_get_descr(result));
	doca_task_free(doca_ipsec_task_sa_destroy_as_task(task));
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

	result = open_doca_device_with_pci(app_cfg->pf.dev_pci_dbdf, task_ipsec_create_is_supported, &app_cfg->pf.dev);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for the secured port: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_dpdk_port_probe(app_cfg->pf.dev, "dv_flow_en=2,dv_xmeta_en=4,fdb_def_rule_en=0,representor=vf[0]");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}
