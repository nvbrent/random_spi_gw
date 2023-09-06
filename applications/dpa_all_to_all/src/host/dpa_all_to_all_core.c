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

#include <stdlib.h>
#include <unistd.h>
#include <infiniband/mlx5dv.h>
#include <limits.h>
#include <math.h>

#include <doca_dev.h>
#include <doca_log.h>

#include "dpa_all_to_all_core.h"

DOCA_LOG_REGISTER(A2A::Core);

/*
 * A struct that includes all needed info on registered kernels and is initialized during linkage by DPACC.
 * Variable name should be the token passed to DPACC with --app-name parameter.
 */
extern struct doca_dpa_app *dpa_all2all_app;

/* IB devices names */
char device1_name[MAX_IB_DEVICE_NAME_LEN];
char device2_name[MAX_IB_DEVICE_NAME_LEN];

/* DOCA DPA all to all kernel function pointer */
doca_dpa_func_t alltoall_kernel;

/*
 * Calculate the width of the integers (according to the number of digits)
 * Note that this functions wouldn't work for n = MIN_INT however in the usage of this function here is guaranteed not
 * to use such values.
 *
 * @n [in]: An integer
 * @return: The width of the integer on success and negative value otherwise
 */
static int
calc_width(int n)
{
	if (n < 0)
		n = -n;
	if (n < 10)
		return 1;
	return floor(log10(n) + 1);
}

/*
 * Print buffer as a matrix
 *
 * @buff [in]: A buffer of integers
 * @columns [in]: Number of columns
 * @rows [in]: Number of rows
 */
static void
print_buff(const int *buff, size_t columns, size_t rows)
{
	int max_wdt1 = 0;
	int max_wdt2 = 0;
	int tmp, wdt;
	const int *tmp_buff = buff;

	for (int i = 0; i < columns * rows; i++) {
		tmp = calc_width(buff[i]);
		max_wdt1 = (tmp > max_wdt1) ? tmp : max_wdt1;
	}
	max_wdt2 = calc_width(rows);
	for (int j = 0; j < rows; j++) {
		printf("Rank %d", j);
		wdt = calc_width(j);
		for (; wdt < max_wdt2; wdt++)
			printf(" ");
		printf(" |");
		for (int i = 0; i < columns - 1; i++) {
			wdt = calc_width(tmp_buff[i]);
			printf("%d   ", tmp_buff[i]);
			for (; wdt < max_wdt1; wdt++)
				printf(" ");
		}
		printf("%d", tmp_buff[columns - 1]);
		wdt = calc_width(tmp_buff[columns - 1]);
		for (; wdt < max_wdt1; wdt++)
			printf(" ");
		printf("|\n");
		tmp_buff += columns;
	}
}

/*
 * Generate a random integer between 0 and 10000
 *
 * @return: A random integer between 0 and 10000 on success and negative value otherwise
 */
static int
compute_random_int(void)
{
	return (rand() % 10000);
}


bool
dpa_device_exists_check(const char *device_name)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs = 0;
	doca_error_t result;
	bool exists = false;
	char ibdev_name[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {0};
	int i = 0;

	/* If it's the default then return true */
	if (strncmp(device_name, IB_DEVICE_DEFAULT_NAME, strlen(IB_DEVICE_DEFAULT_NAME)) == 0)
		return true;

	result = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load DOCA devices list: %s", doca_get_error_string(result));
		return false;
	}

	/* Search device with same dev name*/
	for (i = 0; i < nb_devs; i++) {
		result = doca_devinfo_get_is_dpa_supported(dev_list[i]);
		if (result != DOCA_SUCCESS)
			continue;
		result = doca_devinfo_get_ibdev_name(dev_list[i], ibdev_name, sizeof(ibdev_name));
		if (result != DOCA_SUCCESS)
			continue;

		/* Check if we found the device with the wanted name */
		if (strncmp(device_name, ibdev_name, MAX_IB_DEVICE_NAME_LEN) == 0) {
			exists = true;
			break;
		}
	}

	doca_devinfo_list_destroy(dev_list);

	return exists;
}

/*
 * Open DPA DOCA device
 *
 * @device_name [in]: Wanted IB device name, can be NOT_SET and then a random device IB DPA supported device is chosen
 * @doca_device [out]: An allocated DOCA DPA device on success and NULL otherwise
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
open_dpa_device(const char *device_name, struct doca_dev **doca_device)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs = 0;
	doca_error_t result;
	char ibdev_name[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {0};
	int i = 0;

	result = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load DOCA devices list: %s", doca_get_error_string(result));
		return result;
	}

	/* Search device with same dev name*/
	for (i = 0; i < nb_devs; i++) {
		result = doca_devinfo_get_is_dpa_supported(dev_list[i]);
		if (result != DOCA_SUCCESS)
			continue;
		result = doca_devinfo_get_ibdev_name(dev_list[i], ibdev_name, sizeof(ibdev_name));
		if (result != DOCA_SUCCESS)
			continue;

		/* If a device name was provided then check for it */
		if ((strncmp(device_name, IB_DEVICE_DEFAULT_NAME, strlen(IB_DEVICE_DEFAULT_NAME)) != 0
			&& strncmp(device_name, ibdev_name, MAX_IB_DEVICE_NAME_LEN) != 0))
			continue;

		result = doca_dev_open(dev_list[i], doca_device);
		if (result != DOCA_SUCCESS) {
			doca_devinfo_list_destroy(dev_list);
			DOCA_LOG_ERR("Failed to open DOCA device: %s", doca_get_error_string(result));
			return result;
		}
		break;
	}

	doca_devinfo_list_destroy(dev_list);

	if (*doca_device == NULL) {
		DOCA_LOG_ERR("Couldn't get DOCA device");
		return DOCA_ERROR_NOT_FOUND;
	}

	return result;
}

/*
 * Create DOCA DPA context
 *
 * @resources [in/out]: All to all resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_dpa_context(struct a2a_resources *resources)
{
	doca_error_t result, tmp_result;

	/* Open doca device */
	result = open_dpa_device(resources->device_name, &(resources->doca_device));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("open_dpa_device() failed");
		return result;
	}

	/* Create doca_dpa context */
	result = doca_dpa_create(resources->doca_device, dpa_all2all_app, &(resources->doca_dpa), 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA DPA context: %s", doca_get_error_string(result));
		goto close_doca_dev;
	}

	return result;

close_doca_dev:
	tmp_result = doca_dev_close(resources->doca_device);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to close DOCA DPA device: %s", doca_get_error_string(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

/*
 * Prepare the memory needed for the DOCA DPA all to all, including the sendbuf and recvbufs memory handlers and remote
 * keys, and getting the remote recvbufs addresses from the remote processes.
 *
 * @resources [in/out]: All to all resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
prepare_dpa_a2a_memory(struct a2a_resources *resources)
{
	/* DOCA DPA sendbuf remote memory key */
	uint32_t sendbuf_mem_rkey;
	/* DOCA DPA recvbuf remote memory key */
	uint32_t recvbuf_mem_rkey;
	/* DOCA DPA recvbufs remote memory keys of remote processes*/
	uint32_t *recvbufs_mem_rkeys = NULL;
	/* The recvbufs addresses */
	int **recvbufs = NULL;
	/*
	 * Define DOCA DPA host memory access flags
	 * mem_access_read gives read access to the sendbuf
	 * mem_access_write gives write access to the recvbuf
	 */
	const unsigned int mem_access_read = DOCA_ACCESS_LOCAL_READ_ONLY | DOCA_ACCESS_RDMA_READ;
	const unsigned int mem_access_write = DOCA_ACCESS_LOCAL_READ_WRITE | DOCA_ACCESS_RDMA_WRITE;
	/* Size of the buffers (send and receive) */
	size_t buf_size;
	MPI_Aint lb, extent;
	doca_error_t result, tmp_result;

	/* Get the extent of the datatype and calculate the size of the buffers */
	MPI_Type_get_extent(resources->msg_type, &lb, &extent);
	buf_size = extent * resources->mesg_count * resources->num_ranks;
	resources->extent = extent;

	/* Register DOCA DPA host memory for the sendbuf */
	result = doca_dpa_mem_host_register(resources->doca_dpa, resources->sendbuf, buf_size, mem_access_read,
						&(resources->sendbuf_mem), 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register host memory: %s", doca_get_error_string(result));
		return result;
	}

	/* Export DPA host memory for the sendbuf */
	result = doca_dpa_mem_dev_export(resources->sendbuf_mem, &(resources->sendbuf_mem_handle));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export host memory: %s", doca_get_error_string(result));
		goto unregister_sendbuf;
	}

	/* Get remote memory key of the sendbuf */
	result = doca_dpa_mem_rkey_get(resources->sendbuf_mem, &sendbuf_mem_rkey);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get memory remote key: %s", doca_get_error_string(result));
		goto unregister_sendbuf;
	}

	/* Register DOCA DPA host memory for the recvbuf */
	result = doca_dpa_mem_host_register(resources->doca_dpa, resources->recvbuf, buf_size, mem_access_write,
						&(resources->recvbuf_mem), 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register host memory: %s", doca_get_error_string(result));
		goto unregister_recvbuf;
	}

	/* Get remote memory key of the recvbuf */
	result = doca_dpa_mem_rkey_get(resources->recvbuf_mem, &recvbuf_mem_rkey);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get memory remote key: %s", doca_get_error_string(result));
		goto unregister_sendbuf;
	}

	/* Allocate memory to hold recvbufs remote keys of all the processes */
	recvbufs_mem_rkeys = calloc(resources->num_ranks, sizeof(*recvbufs_mem_rkeys));
	if (recvbufs_mem_rkeys == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for recv rkeys");
		result = DOCA_ERROR_NO_MEMORY;
		goto unregister_sendbuf;
	}

	/* Send the local recvbuf remote key and receive all the remote recvbuf remote keys using Allgather */
	MPI_Allgather(&recvbuf_mem_rkey, sizeof(recvbuf_mem_rkey), MPI_BYTE, recvbufs_mem_rkeys,
			sizeof(recvbuf_mem_rkey), MPI_BYTE, resources->comm);

	/* Allocate DPA memory to hold the recvbufs remote keys */
	result = doca_dpa_mem_alloc(resources->doca_dpa, resources->num_ranks * sizeof(recvbuf_mem_rkey),
					&(resources->devptr_recvbufs_rkeys));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DOCA DPA memory: %s", doca_get_error_string(result));
		goto free_recvbufs_rkeys;
	}

	/* Copy the recvbufs remote keys from the host memory to the device memory */
	result = doca_dpa_h2d_memcpy(resources->doca_dpa, resources->devptr_recvbufs_rkeys, (void *)recvbufs_mem_rkeys,
					resources->num_ranks * sizeof(recvbuf_mem_rkey));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to copy DOCA DPA memory from host to device: %s", doca_get_error_string(result));
		goto free_recvbufs_rkeys_dpa;
	}

	/* Allocate memory to hold the addresses of the recvbufs of all the processes */
	recvbufs = calloc(resources->num_ranks, sizeof(*recvbufs));
	if (recvbufs == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for recv_bufs");
		result = DOCA_ERROR_NO_MEMORY;
		goto free_recvbufs_rkeys_dpa;
	}

	/* Send the local recvbuf address and receive all the remote recvbufs addresses using Allgather */
	MPI_Allgather(&(resources->recvbuf), sizeof(resources->recvbuf), MPI_BYTE, recvbufs, sizeof(*recvbufs), MPI_BYTE, resources->comm);

	/* Allocate DPA memory to hold the recvbufs addresses */
	result = doca_dpa_mem_alloc(resources->doca_dpa, resources->num_ranks * sizeof(*recvbufs), &(resources->devptr_recvbufs));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DOCA DPA memory: %s", doca_get_error_string(result));
		goto free_recvbufs;
	}

	/* Copy the recvbufs addresses from the host memory to the device memory */
	result = doca_dpa_h2d_memcpy(resources->doca_dpa, resources->devptr_recvbufs, (void *)recvbufs,
					resources->num_ranks * sizeof(*recvbufs));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to copy DOCA DPA memory from host to device: %s", doca_get_error_string(result));
		goto free_recvbufs_dpa;
	}

	resources->rp_remote_kernel_events = calloc(resources->num_ranks, sizeof(*(resources->rp_remote_kernel_events)));
	if (resources->rp_remote_kernel_events == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for rp_remote_kernel_events");
		result = DOCA_ERROR_NO_MEMORY;
		goto free_recvbufs_dpa;
	}

	/* Send the local process' remote kernel event and receive all the remote kernel events using Allgather */
	MPI_Alltoall(resources->lp_remote_kernel_events, sizeof(*(resources->lp_remote_kernel_events)), MPI_BYTE,
			resources->rp_remote_kernel_events, sizeof(*(resources->rp_remote_kernel_events)), MPI_BYTE, resources->comm);

	/* Free the local process' remote kernel event since we don't need them anymore */
	free(resources->lp_remote_kernel_events);

	/* Allocate DPA memory to hold the remote kernel events */
	result = doca_dpa_mem_alloc(resources->doca_dpa, resources->num_ranks * sizeof(*(resources->rp_remote_kernel_events)), &(resources->devptr_rp_remote_kernel_events));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DOCA DPA memory: %s", doca_get_error_string(result));
		goto free_remote_kernel_events;
	}

	/* Copy the remote kernel events from the host memory to the device memory */
	result = doca_dpa_h2d_memcpy(resources->doca_dpa, resources->devptr_rp_remote_kernel_events, (void *)resources->rp_remote_kernel_events,
					resources->num_ranks * sizeof(*(resources->rp_remote_kernel_events)));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to copy DOCA DPA memory from host to device: %s", doca_get_error_string(result));
		goto free_rp_remote_kernel_events_dpa;
	}

	/* Allocate DPA memory to hold the local remote kernel events */
	result = doca_dpa_mem_alloc(resources->doca_dpa, resources->num_ranks * sizeof(*(resources->kernel_events_handle)), &(resources->devptr_kernel_events_handle));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DOCA DPA memory: %s", doca_get_error_string(result));
		goto free_rp_remote_kernel_events_dpa;
	}

	/* Copy the remote kernel events from the host memory to the device memory */
	result = doca_dpa_h2d_memcpy(resources->doca_dpa, resources->devptr_kernel_events_handle, (void *)resources->kernel_events_handle,
					resources->num_ranks * sizeof(*(resources->kernel_events_handle)));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to copy DOCA DPA memory from host to device: %s", doca_get_error_string(result));
		goto free_kernel_events_handle_dpa;
	}

	/* Free the recvbufs remote keys host memory since it's no longer used */
	free(recvbufs_mem_rkeys);
	/* Free the recvbufs addresses host memory since it's no longer used */
	free(recvbufs);

	return result;

free_kernel_events_handle_dpa:
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_kernel_events_handle);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_rp_remote_kernel_events_dpa:
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_rp_remote_kernel_events);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_remote_kernel_events:
	free(resources->rp_remote_kernel_events);
free_recvbufs_dpa:
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_recvbufs);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_recvbufs:
	free(recvbufs);
free_recvbufs_rkeys_dpa:
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_recvbufs_rkeys);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_recvbufs_rkeys:
	free(recvbufs_mem_rkeys);
unregister_recvbuf:
	tmp_result = doca_dpa_mem_unregister(resources->recvbuf_mem);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to unregister DOCA DPA host memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
unregister_sendbuf:
	tmp_result = doca_dpa_mem_unregister(resources->sendbuf_mem);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to unregister DOCA DPA host memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

/*
 * Connect the local process' DOCA DPA endpoints to the remote processes' DOCA DPA endpoints.
 * Endpoint number i in each process would be connected to an endpoint of in process rank i.
 *
 * @resources [in]: All to all resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
connect_dpa_a2a_endpoints(struct a2a_resources *resources)
{
	/* Local endpoint address */
	struct doca_dpa_ep_addr *addr = NULL;
	/* Remote endpoint address */
	struct doca_dpa_ep_addr *remote_addr = NULL;
	/* Length of addresses */
	size_t addr_len, remote_addr_len;
	/* Tags for the MPI send and recv for address and address length */
	const int addr_tag = 1;
	const int addr_len_tag = 2;
	/* MPI request used for syncronization between processes */
	MPI_Request reqs[2];
	doca_error_t result, tmp_result;

	for (int i = 0; i < resources->num_ranks; i++) {
		/*
		 * Rank of the remote process that we are
		 * going to send to the local endpoint address
		 */
		int send_rank = (resources->my_rank + i) % resources->num_ranks;
		/*
		 * Rank of the remote process that we are going
		 * to receive from the remote endpoint address
		 */
		int recv_rank = (resources->my_rank - i + resources->num_ranks) % resources->num_ranks;
		/*
		 * Get the local endpoint address with the index
		 * same as the rank of the process we are going to send to
		 */
		result = doca_dpa_ep_addr_get(resources->eps[send_rank], &addr, &addr_len);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to get DOCA DPA endpoint address: %s", doca_get_error_string(result));
			return result;
		}

		/* Send and receive the addresses using MPI Isend and Recv */
		MPI_Isend(&addr_len, 1, MPI_INT64_T, send_rank, addr_len_tag, resources->comm, &reqs[0]);
		MPI_Isend(addr, addr_len, MPI_CHAR, send_rank, addr_tag,  resources->comm, &reqs[1]);

		MPI_Recv(&remote_addr_len, 1, MPI_INT64_T, recv_rank, addr_len_tag, resources->comm, MPI_STATUS_IGNORE);
		remote_addr = malloc(remote_addr_len);
		if (remote_addr == NULL) {
			DOCA_LOG_ERR("Failed to allocate memory for remote endpoint address");
			tmp_result = doca_dpa_ep_addr_free(addr);
			if (tmp_result != DOCA_SUCCESS)
				DOCA_LOG_ERR("Failed to free DOCA DPA endpoint address: %s", doca_get_error_string(result));
			return DOCA_ERROR_NO_MEMORY;
		}
		MPI_Recv(remote_addr, remote_addr_len, MPI_CHAR, recv_rank, addr_tag, resources->comm, MPI_STATUS_IGNORE);

		/*
		 * Connect to the endpoint of the remote process.
		 * The local endpoint of index i will be connected to an endpoint of a remote process of rank i.
		 */
		result = doca_dpa_ep_connect(resources->eps[recv_rank], remote_addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to get connect DOCA DPA endpoint: %s", doca_get_error_string(result));
			free(remote_addr);
			tmp_result = doca_dpa_ep_addr_free(addr);
			if (tmp_result != DOCA_SUCCESS)
				DOCA_LOG_ERR("Failed to free DOCA DPA endpoint address: %s", doca_get_error_string(result));
			return result;
		}

		/* Wait until the send requests have been received */
		MPI_Waitall(2, reqs, MPI_STATUS_IGNORE);

		free(remote_addr);
		result = doca_dpa_ep_addr_free(addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to free DOCA DPA endpoint address: %s", doca_get_error_string(result));
			return result;
		}
	}

	return result;
}

/*
 * Prepare the DOCA DPA endpoint, which includes creating the endpoints and their handlers, connecting them to
 * the remote processes' endpoints and allocating DOCA DPA device memory to hold the handlers so that they can be used
 * in a DOCA DPA kernel function.
 *
 * @resources [in/out]: All to all resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
prepare_dpa_a2a_endpoints(struct a2a_resources *resources)
{
	/* Access flags for the endpoints */
	const unsigned int ep_access = DOCA_ACCESS_LOCAL_READ_WRITE | DOCA_ACCESS_RDMA_READ |
					DOCA_ACCESS_RDMA_WRITE | DOCA_ACCESS_RDMA_ATOMIC;
	/* DOCA DPA endpoints handlers */
	doca_dpa_dev_ep_t *eps_handlers;
	int i;
	doca_error_t result, tmp_result;

	/* Create endpoints as number of the processes */
	resources->eps = calloc(resources->num_ranks, sizeof(*(resources->eps)));
	if (resources->eps == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for DOCA DPA endpoints");
		return DOCA_ERROR_NO_MEMORY;
	}
	for (i = 0; i < resources->num_ranks; i++) {
		result = doca_dpa_ep_create(resources->worker, ep_access, &(resources->eps[i]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create DOCA DPA endpoint: %s", doca_get_error_string(result));
			goto destroy_eps;
		}
	}

	/* Connect local endpoints to the remote endpoints */
	result = connect_dpa_a2a_endpoints(resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA DPA endpoint: %s", doca_get_error_string(result));
		goto destroy_eps;
	}

	/* Create device handlers for the endpoints */
	eps_handlers = calloc(resources->num_ranks, sizeof(*eps_handlers));
	if (eps_handlers == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for DOCA DPA device endpoint handlers");
		goto destroy_eps;
	}
	for (int j = 0; j < resources->num_ranks; j++) {
		result = doca_dpa_ep_dev_export(resources->eps[j], &(eps_handlers[j]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to export DOCA DPA endpoint: %s", doca_get_error_string(result));
			goto free_eps_handlers;
		}
	}

	/* Allocate DPA memory to hold the endpoints handlers */
	result = doca_dpa_mem_alloc(resources->doca_dpa, sizeof(*eps_handlers) * resources->num_ranks,
					&(resources->devptr_eps));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DOCA DPA memory: %s", doca_get_error_string(result));
		goto free_eps_handlers;
	}

	/* Copy the endpoints handlers from the host memory to the device memory */
	result = doca_dpa_h2d_memcpy(resources->doca_dpa, resources->devptr_eps, (void *)eps_handlers,
					sizeof(*eps_handlers) * resources->num_ranks);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to copy DOCA DPA memory from host to device: %s", doca_get_error_string(result));
		goto free_eps_handlers_dpa;
	}

	/* Free the endpoints handlers */
	free(eps_handlers);

	return result;

free_eps_handlers_dpa:
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_eps);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_eps_handlers:
	free(eps_handlers);
destroy_eps:
	for (int j = 0; j < i; j++) {
		tmp_result = doca_dpa_ep_destroy(resources->eps[j]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA DPA endpoint: %s", doca_get_error_string(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}
	free(resources->eps);

	return result;
}

/*
 * Create DOCA sync event to be published by the DPA and subscribed by the CPU
 *
 * @doca_dpa [in]: DOCA DPA context
 * @doca_device [in]: DOCA device
 * @comp_event [out]: Created DOCA sync event that is published by the DPA and subscribed by the CPU
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_doca_dpa_completion_sync_event(struct doca_dpa *doca_dpa, struct doca_dev *doca_device, struct doca_sync_event **comp_event)
{
	doca_error_t result, tmp_result;

	result = doca_sync_event_create(comp_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA sync event: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_sync_event_publisher_add_location_dpa(*comp_event, doca_dpa);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DPA as publisher for DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_comp_event;
	}

	result = doca_sync_event_subscriber_add_location_cpu(*comp_event, doca_device);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set CPU as subscriber for DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_comp_event;
	}

	result = doca_sync_event_start(*comp_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_comp_event;
	}

	return result;

destroy_comp_event:
	tmp_result = doca_sync_event_destroy(*comp_event);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA sync event: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);

	}
	return result;
}

/*
 * Create DOCA sync event to be published and subscribed by the DPA
 *
 * @doca_dpa [in]: DOCA DPA context
 * @kernel_event [out]: Created DOCA sync event that is published and subscribed by the DPA
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_doca_dpa_kernel_sync_event(struct doca_dpa *doca_dpa, struct doca_sync_event **kernel_event)
{
	doca_error_t result, tmp_result;

	result = doca_sync_event_create(kernel_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA sync event: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_sync_event_publisher_add_location_dpa(*kernel_event, doca_dpa);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DPA as publisher for DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_kernel_event;
	}

	result = doca_sync_event_subscriber_add_location_dpa(*kernel_event, doca_dpa);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DPA as subscriber for DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_kernel_event;
	}

	result = doca_sync_event_start(*kernel_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start DOCA sync event: %s", doca_get_error_string(result));
		goto destroy_kernel_event;
	}

	return result;

destroy_kernel_event:
	tmp_result = doca_sync_event_destroy(*kernel_event);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA sync event: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);

	}
	return result;
}

/*
 * Create the needed DOCA sync events for the All to All:
 *	One kernel completion event, the publisher is the DPA and the subscriber is the host.
 *	Number of ranks kernel events, the publisher and subscriber is the DPA.
 *
 * @resources [in/out]: All to all resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_dpa_a2a_events(struct a2a_resources *resources)
{
	int i;
	doca_error_t result, tmp_result;

	/* Create DOCA DPA kernel completion event*/
	result = create_doca_dpa_completion_sync_event(resources->doca_dpa, resources->doca_device, &(resources->comp_event));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create host completion event: %s", doca_get_error_string(result));
		return result;
	}

	/* Create DOCA DPA events to be used inside of the kernel */
	resources->kernel_events = calloc(resources->num_ranks, sizeof(*(resources->kernel_events)));
	if (resources->kernel_events == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for kernel events");
		result = DOCA_ERROR_NO_MEMORY;
		goto destroy_comp_event;
	}
	for (i = 0; i < resources->num_ranks; i++) {
		result = create_doca_dpa_kernel_sync_event(resources->doca_dpa, &(resources->kernel_events[i]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create kernel event: %s", doca_get_error_string(result));
			goto destroy_kernel_events;
		}
	}

	/* Create DOCA DPA events handles */
	resources->kernel_events_handle = calloc(resources->num_ranks, sizeof(*(resources->kernel_events_handle)));
	if (resources->kernel_events_handle == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for kernel events handles");
		result = DOCA_ERROR_NO_MEMORY;
		goto destroy_kernel_events_handles;
	}

	for (int j = 0; j < resources->num_ranks; j++) {
		/* Export the kernel events */
		result = doca_sync_event_export_to_dpa(resources->kernel_events[j], resources->doca_dpa, &(resources->kernel_events_handle[j]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to export kernel event: %s", doca_get_error_string(result));
			goto destroy_kernel_events_handles;
		}
	}

	/* Remote export the kernel events */
	resources->lp_remote_kernel_events = calloc(resources->num_ranks, sizeof(*(resources->lp_remote_kernel_events)));
	if (resources->lp_remote_kernel_events == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for kernel events handles");
		result = DOCA_ERROR_NO_MEMORY;
		goto destroy_remote_kernel_events;
	}
	for (int j = 0; j < resources->num_ranks; j++) {
		/* Export the kernel events */
		result = doca_sync_event_export_remote(resources->kernel_events[j], &(resources->lp_remote_kernel_events[j]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to remote export kernel event: %s", doca_get_error_string(result));
			goto destroy_remote_kernel_events;
		}
	}

	return result;

destroy_remote_kernel_events:
	free(resources->lp_remote_kernel_events);
destroy_kernel_events_handles:
	free(resources->kernel_events_handle);
destroy_kernel_events:
	for (int j = 0; j < i; j++) {
		tmp_result = doca_sync_event_destroy(resources->kernel_events[j]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy kernel_event: %s", doca_get_error_string(result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}
	free(resources->kernel_events);
destroy_comp_event:
	tmp_result = doca_sync_event_destroy(resources->comp_event);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy comp_event: %s", doca_get_error_string(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
dpa_a2a_init(struct a2a_resources *resources)
{
	doca_error_t result, tmp_result;

	/* divide the two devices (can be the same) on all processes equally */
	if (resources->my_rank >= ((double)resources->num_ranks/2.0))
		strcpy(resources->device_name, device2_name);
	else
		strcpy(resources->device_name, device1_name);

	/* Create DOCA DPA context*/
	result = create_dpa_context(resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA DPA device: %s", doca_get_error_string(result));
		return result;
	}

	result = create_dpa_a2a_events(resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA DPA events: %s", doca_get_error_string(result));
		goto destroy_dpa;
	}

	result = doca_dpa_worker_create(resources->doca_dpa, &(resources->worker), 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA DPA worker: %s", doca_get_error_string(result));
		goto destroy_events;
	}

	/* Prepare DOCA DPA endpoints all to all resources */
	result = prepare_dpa_a2a_endpoints(resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to prepare DOCA DPA endpoints resources: %s", doca_get_error_string(result));
		goto destroy_worker;
	}

	/* Prepare DOCA DPA all to all memory */
	result = prepare_dpa_a2a_memory(resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to prepare DOCA DPA endpoints resources: %s", doca_get_error_string(result));
		goto destroy_endpoints;
	}

	return result;

destroy_endpoints:
	/* Destroy DOCA DPA endpoints */
	for (int i = 0; i < resources->num_ranks; i++) {
		tmp_result = doca_dpa_ep_destroy(resources->eps[i]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA DPA endpoint: %s", doca_get_error_string(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}
	free(resources->eps);
destroy_worker:
	/* Destroy DOCA DPA worker */
	tmp_result = doca_dpa_worker_destroy(resources->worker);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA DPA worker: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_events:
	free(resources->lp_remote_kernel_events);
	free(resources->kernel_events_handle);
	for (int i = 0; i < resources->num_ranks; i++) {
		tmp_result = doca_sync_event_destroy(resources->kernel_events[i]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy kernel_event: %s", doca_get_error_string(result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}
	free(resources->kernel_events);
	tmp_result = doca_sync_event_destroy(resources->comp_event);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy comp_event: %s", doca_get_error_string(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_dpa:
	/* Destroy DOCA DPA context */
	tmp_result = doca_dpa_destroy(resources->doca_dpa);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA DPA context: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	/* Close DOCA device */
	tmp_result = doca_dev_close(resources->doca_device);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to close DOCA device: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
dpa_a2a_destroy(struct a2a_resources *resources)
{
	doca_error_t result, tmp_result;

	/* Free DPA device memeory*/
	result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_kernel_events_handle);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));

	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_rp_remote_kernel_events);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	free(resources->rp_remote_kernel_events);
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_recvbufs);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_recvbufs_rkeys);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	tmp_result = doca_dpa_mem_free(resources->doca_dpa, resources->devptr_eps);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to free DOCA DPA device memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	/* Unregister DOCA DPA host memory*/
	tmp_result = doca_dpa_mem_unregister(resources->recvbuf_mem);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to unregister DOCA DPA host memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	tmp_result = doca_dpa_mem_unregister(resources->sendbuf_mem);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to unregister DOCA DPA host memory: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	/* Destroy DOCA DPA endpoints*/
	for (int i = 0; i < resources->num_ranks; i++) {
		tmp_result = doca_dpa_ep_destroy(resources->eps[i]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA DPA endpoint: %s", doca_get_error_string(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}
	free(resources->eps);

	/* Destroy DOCA DPA worker */
	tmp_result = doca_dpa_worker_destroy(resources->worker);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA DPA worker: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	/* Free kernel events handles */
	free(resources->kernel_events_handle);
	/* Destroy DOCA DPA kernel events */
	for (int i = 0; i < resources->num_ranks; i++) {
		tmp_result = doca_sync_event_destroy(resources->kernel_events[i]);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy kernel_event: %s", doca_get_error_string(result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}

	/* Destroy DOCA DPA completion event */
	tmp_result = doca_sync_event_destroy(resources->comp_event);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy comp_event: %s", doca_get_error_string(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	/* Destroy DOCA DPA context */
	tmp_result = doca_dpa_destroy(resources->doca_dpa);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA DPA context: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	/* Close DOCA device */
	tmp_result = doca_dev_close(resources->doca_device);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to close DOCA device: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
dpa_a2a_req_finalize(struct dpa_a2a_request *req)
{
	doca_error_t result;

	if (req->resources == NULL)
		return DOCA_SUCCESS;

	result = dpa_a2a_destroy(req->resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy a2a resources: %s", doca_get_error_string(result));
		return result;
	}
	free(req->resources);
	req->resources = NULL;

	return result;
}

doca_error_t
dpa_a2a_req_wait(struct dpa_a2a_request *req)
{
	doca_error_t result;

	if (req->resources == NULL) {
		DOCA_LOG_ERR("Failed to wait for comp_event");
		return DOCA_ERROR_UNEXPECTED;
	}
	result = doca_sync_event_wait_gt(req->resources->comp_event, req->resources->a2a_seq_num - 1, SYNC_EVENT_MASK_FFS);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to wait for comp_event: %s", doca_get_error_string(result));

	return result;
}

doca_error_t
dpa_ialltoall(void *sendbuf, int sendcount, MPI_Datatype sendtype, void *recvbuf, int recvcount,
		 MPI_Datatype recvtype, MPI_Comm comm, struct dpa_a2a_request *req)
{
	int num_ranks, my_rank;
	/* Number of threads to run the kernel */
	unsigned int num_threads;
	doca_error_t result, tmp_result;

	/* If current process is not part of any communicator then exit */
	if (comm == MPI_COMM_NULL)
		return DOCA_SUCCESS;

	/* Get the rank of the current process */
	MPI_Comm_rank(comm, &my_rank);
	/* Get the number of processes */
	MPI_Comm_size(comm, &num_ranks);
	if (!req->resources) {
		req->resources = malloc(sizeof(*(req->resources)));
		if (req->resources == NULL) {
			DOCA_LOG_ERR("Failed to allocate a2a resources");
			return DOCA_ERROR_NO_MEMORY;
		}
		/* Initialize all to all resources */
		req->resources->a2a_seq_num = 0;
		req->resources->comm = comm;
		req->resources->mesg_count = sendcount;
		req->resources->msg_type = sendtype;
		req->resources->my_rank = my_rank;
		req->resources->num_ranks = num_ranks;
		req->resources->sendbuf = sendbuf;
		req->resources->recvbuf = recvbuf;
		result = dpa_a2a_init(req->resources);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to initialize alltoall resources: %s", doca_get_error_string(result));
			free(req->resources);
			return result;
		}
	}

	/* The number of threads should be the minimum between the number of processes and the maximum number of threads */
	num_threads = (req->resources->num_ranks < MAX_NUM_THREADS) ? req->resources->num_ranks : MAX_NUM_THREADS;

	/* Increment the sequence number */
	req->resources->a2a_seq_num++;

	/* Launch all to all kernel*/
	result = doca_dpa_kernel_launch_update_set(req->resources->doca_dpa, NULL, 0, req->resources->comp_event,
					req->resources->a2a_seq_num, num_threads,
					&alltoall_kernel, req->resources->devptr_eps, sendbuf,
					req->resources->sendbuf_mem_handle, (uint64_t)sendcount, (uint64_t)req->resources->extent,
					(uint64_t)num_ranks, (uint64_t)my_rank, req->resources->devptr_recvbufs,
					req->resources->devptr_recvbufs_rkeys, req->resources->devptr_kernel_events_handle,
					req->resources->devptr_rp_remote_kernel_events, req->resources->a2a_seq_num);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to launch alltoall kernel: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

doca_error_t
dpa_alltoall(void *sendbuf, int sendcount, MPI_Datatype sendtype, void *recvbuf, int recvcount,
		 MPI_Datatype recvtype, MPI_Comm comm)
{
	struct dpa_a2a_request req = {.resources = NULL};
	doca_error_t result;

	/* Run DPA All to All non-blocking */
	result = dpa_ialltoall(sendbuf, sendcount, sendtype, recvbuf, recvcount, recvtype, comm, &req);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("dpa_ialltoall() failed: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait till the DPA All to All finishes */
	result = dpa_a2a_req_wait(&req);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("dpa_a2a_req_wait() failed: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait until all processes finish waiting */
	MPI_Barrier(comm);

	/* Finalize the request */
	result = dpa_a2a_req_finalize(&req);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("dpa_a2a_req_finalize() failed: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

doca_error_t
dpa_a2a(int argc, char **argv, struct a2a_config *cfg)
{
	int my_rank, num_ranks, i;
	size_t buff_size, msg_size, msg_count;
	int *send_buf, *recv_buf, *send_buf_all, *recv_buf_all;
	doca_error_t result;

	/* Initialize MPI variables */
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &num_ranks);

	if (num_ranks > MAX_NUM_PROC) {
		if (my_rank == 0)
			DOCA_LOG_ERR("Invalid number of processes. Maximum number of processes is %d", MAX_NUM_PROC);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/*
	 * Define message size, message count and buffer size
	 * If it's the default then the message size is the number of processes times size of one integer
	 */
	if (cfg->msgsize == MESSAGE_SIZE_DEFAULT_LEN)
		msg_size = num_ranks * sizeof(int);
	else
		msg_size = (size_t)cfg->msgsize;
	msg_count = (msg_size / num_ranks) / sizeof(int);
	if (msg_count == 0) {
		if (my_rank == 0)
			DOCA_LOG_ERR("Message size %lu too small for the number of processes. Should be at least %lu"
					, msg_size, num_ranks * sizeof(int));
		return DOCA_ERROR_INVALID_VALUE;
	}

	buff_size = msg_size / sizeof(int);

	/* Set devices names */
	strcpy(device1_name, cfg->device1_name);
	if (strncmp(cfg->device2_name, IB_DEVICE_DEFAULT_NAME, strlen(IB_DEVICE_DEFAULT_NAME)) != 0)
		strcpy(device2_name, cfg->device2_name);
	else
		strcpy(device2_name, cfg->device1_name);

	if (my_rank == 0)
		DOCA_LOG_INFO("Number of processes = %d, message size = %lu, message count = %lu, buffer size = %lu"
				, num_ranks, msg_size, msg_count, buff_size);

	/* Allocate and initialize the buffers */
	send_buf = calloc(buff_size, sizeof(int));
	recv_buf = calloc(buff_size, sizeof(int));
	send_buf_all = calloc(num_ranks*buff_size, sizeof(int));
	recv_buf_all = calloc(num_ranks*buff_size, sizeof(int));

	if (send_buf == NULL || recv_buf == NULL || send_buf_all == NULL || recv_buf_all == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for send/recv buffers");
		result = DOCA_ERROR_NO_MEMORY;
		goto destroy_bufs;
	}

	/* Seed srand */
	srand(time(NULL) + my_rank);
	for (i = 0; i < buff_size; i++)
		send_buf[i] = compute_random_int();

	MPI_Barrier(MPI_COMM_WORLD);

	/* Perform DPA All to All */
	result = dpa_alltoall(send_buf, msg_count, MPI_INT, recv_buf, msg_count, MPI_INT, MPI_COMM_WORLD);
	if (result != DOCA_SUCCESS) {
		if (my_rank == 0)
			DOCA_LOG_ERR("DPA MPI alltoall failed: %s", doca_get_error_string(result));
		goto destroy_bufs;
	}

	/* Receive all the sendbuf and the recvbuf from all the processes to print */
	MPI_Allgather(send_buf, buff_size, MPI_INT, send_buf_all, buff_size, MPI_INT, MPI_COMM_WORLD);
	MPI_Allgather(recv_buf, buff_size, MPI_INT, recv_buf_all, buff_size, MPI_INT, MPI_COMM_WORLD);
	if (my_rank == 0) {
		printf("         ------------send buffs----------------------\n");
		print_buff(send_buf_all, buff_size, num_ranks);
		printf("         ------------recv buffs----------------------\n");
		print_buff(recv_buf_all, buff_size, num_ranks);
	}

destroy_bufs:
	free(send_buf);
	free(send_buf_all);
	free(recv_buf);
	free(recv_buf_all);

	return result;
}

