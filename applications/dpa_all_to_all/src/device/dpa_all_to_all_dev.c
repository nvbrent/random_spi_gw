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

#include <doca_dpa_dev.h>
#include <doca_dpa_dev_sync_event.h>

#define SYNC_EVENT_MASK_FFS (0xFFFFFFFFFFFFFFFF)	/* Mask for doca_dpa_dev_sync_event_wait_gt() wait value */

/*
 * Alltoall kernel function.
 * Performs RDMA write operations using doca_dpa_dev_put_nb() from local_addr to remote_addrs.
 *
 * @eps [in]: An array of DOCA DPA endpoint handlers
 * @local_addr [in]: Local buffer for alltoall
 * @local_mem_handle [in]: Memory handle for local_addr
 * @count [in]: Number of elements to write
 * @type_length [in]: Length of each element
 * @num_ranks [in]: Number of the MPI ranks
 * @my_rank [in]: The rank of the current process
 * @remote_addrs [in]: Remote host buffers for alltoall
 * @remote_keys [in]: Memory keys for remote host buffers
 * @local_events [in]: Communication events that will be updated by remote MPI ranks
 * @remote_events [in]: Communication events on other nodes that will be updated by this rank
 * @a2a_seq_num [in]: The number of times we called the alltoall_kernel in iterations
 */
__dpa_global__ void alltoall_kernel(doca_dpa_dev_uintptr_t eps, uint64_t local_addr, doca_dpa_dev_mem_t local_mem_handle,
					uint64_t count, uint64_t type_length, uint64_t num_ranks, uint64_t my_rank,
					doca_dpa_dev_uintptr_t remote_addrs, doca_dpa_dev_uintptr_t remote_keys,
					doca_dpa_dev_uintptr_t local_events, doca_dpa_dev_uintptr_t remote_events, uint64_t a2a_seq_num)
{
	/* Convert the sendbuf and recvbufs addresses to bytes pointer */
	char *local_addr_ptr = (char *)local_addr;
	char **remote_addrs_ptr = (char **)remote_addrs;
	/* Convert the remote keys DPA device pointer to remote key pointer */
	uint32_t *remote_keys_ptr = (uint32_t *)remote_keys;
	/* Convert the endpoints DPA device pointer to endpoint pointer */
	doca_dpa_dev_ep_t *eps_ptr = (doca_dpa_dev_ep_t *)eps;
	/* Convert the local events DPA device pointer to local events pointer */
	doca_dpa_dev_sync_event_t *local_events_ptr = (doca_dpa_dev_sync_event_t *)local_events;
	/* Convert the remote events DPA device pointer to remote events pointer */
	doca_dpa_dev_sync_event_remote_t *remote_events_ptr = (doca_dpa_dev_sync_event_remote_t *)remote_events;
	/* Get the rank of current thread that is running */
	unsigned int thread_rank = doca_dpa_dev_thread_rank();
	/* Get the number of all threads that are running this kernel */
	unsigned int num_threads = doca_dpa_dev_num_threads();
	unsigned int i;

	/*
	 * Each process should perform as the number of processes RDMA write operations with local and remote addresses
	 * according to the rank of the local process and the rank of the remote processes (we iterate over the rank
	 * of the remote process).
	 * Each process runs num_threads threads on this kernel so we divide the number RDMA write operations (which is
	 * the number of processes) by the number of threads.
	 */
	for (i = thread_rank; i < num_ranks; i += num_threads)
		doca_dpa_dev_put_signal_set_nb(eps_ptr[i],
					(uint64_t)(local_addr_ptr + (i * count * type_length)),
					local_mem_handle, type_length * count,
					(uint64_t)(remote_addrs_ptr[i] + (count * my_rank * type_length)),
					remote_keys_ptr[i],
					remote_events_ptr[i], a2a_seq_num);


	/*
	 * Each thread should wait on his local events to make sure that the
	 * remote processes have finished writing on its endpoints.
	 * Each thread should also synchronize its endpoints to make sure
	 * that the doca_dpa_dev_put_signal_nb() call has finished
	 */
	for (i = thread_rank; i < num_ranks; i += num_threads) {
		doca_dpa_dev_sync_event_wait_gt(local_events_ptr[i], a2a_seq_num - 1, SYNC_EVENT_MASK_FFS);
		doca_dpa_dev_ep_synchronize(eps_ptr[i]);
	}
}
