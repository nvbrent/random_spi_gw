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
#include <signal.h>
#include <fcntl.h>

#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_ipsec.h>

#include <dpdk_utils.h>
#include <pack.h>

#include <random_spi_gw.h>

// For VF-to-uplink traffic, assign a random SPI to simulate
// traffic between a large number of peers, which will potentially
// thrash the ICM Cache.
// For Uplink-to-VF traffic, simply match on SPI, decrypt and forward
// to the VF.
//
//       --Empty root pipe--      --Hash pipe? Basic pipe?--
//       [match:  null]           [match: pkt.rand_meta]
// VF -> [action: null]        -> [action: encrypt w/ SPI] -> PF
//       [dest: encrypt pipe]     [dest: uplink port]
//
//       [match: SPI]
// PF -> [action: decrypt] -> VF
//       [dest: VF port]
//

DOCA_LOG_REGISTER(RANDOM_SPI_GW);

#define DEFAULT_NB_CORES 4		/* Default number of running cores */
#define PACKET_BURST 32			/* The number of packets in the rx queue */
#define NB_TX_BURST_TRIES 5		/* Number of tries for sending batch of packets */
#define WINDOW_SIZE 64			/* The size of the replay window */
#define QUEUE_DEPTH (512)	   /* DOCA Flow queue depth */

#define KEY_LEN_BITS 256
#define KEY_LEN_BYTES (KEY_LEN_BITS / 8)

#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define TIMEOUT_USEC (10 * 1000) // timeout process-entries after 10 millisec


static bool force_quit;			/* Set when signal is received */

/*
 * Signals handler function to handle SIGINT and SIGTERM signals
 *
 * @signum [in]: signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		force_quit = true;
	}
}

void idx_to_key256(uint32_t n, uint8_t *key)
{
	uint32_t *key_words = (uint32_t*)key;
	for (uint32_t i=0; i<KEY_LEN_BYTES / sizeof(uint32_t); i++) {
		key_words[i] = n;
	}
}

uint32_t idx_to_spi(uint32_t n)
{
	return n + 0x8000;
}

/*
 * Entry processing callback
 *
 * @entry [in]: entry pointer
 * @pipe_queue [in]: queue identifier
 * @status [in]: DOCA Flow entry status
 * @op [in]: DOCA Flow entry operation
 * @user_ctx [out]: user context
 */
static void
check_for_valid_entry(struct doca_flow_pipe_entry *entry, uint16_t pipe_queue,
		      enum doca_flow_entry_status status, enum doca_flow_entry_op op, void *user_ctx)
{
	(void)entry;
	(void)op;
	(void)pipe_queue;

	// TODO: track via user_ctx/entry_status
	// struct entries_status *entry_status = (struct entries_status *)user_ctx;

	// if (entry_status == NULL || op != DOCA_FLOW_ENTRY_OP_ADD)
	// 	return;
	// if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
	// 	//DOCA_LOG_WARN("%s: status = %d, wanted %d", __FUNCTION__, status, DOCA_FLOW_ENTRY_STATUS_SUCCESS);
	// 	entry_status->failure = true; /* set failure to true if processing failed */
	// }
	// entry_status->nb_processed++;
	// entry_status->entries_in_queue--;
}

/*
 * Create DOCA Flow port by port id
 *
 * @port_id [in]: port ID
 * @port [out]: pointer to port handler
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_doca_flow_port(int port_id, struct doca_flow_port **port)
{
	const int max_port_str_len = 128;
	char port_id_str[max_port_str_len];
	snprintf(port_id_str, max_port_str_len, "%d", port_id);

	struct doca_flow_port_cfg port_cfg = {
		.port_id = port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str,
	};
	return doca_flow_port_start(&port_cfg, port);
}

doca_error_t
random_spi_gw_init_doca_flow(
	struct random_spi_gw_config *app_cfg, 
	int nb_queues)
{
	/* init doca flow with crypto shared resources */
	struct doca_flow_cfg flow_cfg = {
		.queues = nb_queues,
		.mode_args = "switch,hws,isolated",
		.queue_depth = QUEUE_DEPTH,
		.cb = check_for_valid_entry,
		.resource = {
			.nb_counters = app_cfg->num_spi * 2,
		},
		.nr_shared_resources = {
			[DOCA_FLOW_SHARED_RESOURCE_CRYPTO] = app_cfg->num_spi * 2,
		},
	};
	doca_error_t result = doca_flow_init(&flow_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_get_error_string(result));
		return result;
	}

	/* search for the probed devices */
	int port_id = 0;
	if (!rte_eth_dev_is_valid_port(port_id)) {
		DOCA_LOG_ERR("Failed to init DOCA Flow switch port");
		return DOCA_ERROR_INITIALIZATION;
	}

	struct doca_flow_port *port = NULL;
	result = create_doca_flow_port(port_id, &port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow port: %s", doca_get_error_string(result));
		doca_flow_destroy();
		return result;
	}

	// make sure we are using the port which owns the eswitch
	app_cfg->pf.port = doca_flow_port_switch_get(port);

	return DOCA_SUCCESS;
}

static struct doca_ipsec_sa*
create_security_assoc(
	struct random_spi_gw_config *app_cfg,
	uint8_t *key_256, 
	enum doca_ipsec_direction dir)
{
	struct doca_ipsec_sa_create_job sa_create = {
		.base = (struct doca_job) {
			.type = DOCA_IPSEC_JOB_SA_CREATE,
			.flags = DOCA_JOB_FLAGS_NONE,
			.ctx = app_cfg->doca_ctx,
			.user_data.u64 = DOCA_IPSEC_JOB_SA_CREATE,
		},
		.sa_attrs = {
			.key = {
				.type = DOCA_ENCRYPTION_KEY_AESGCM_256,
				.aes_gcm = {
					.implicit_iv = 0,
					.salt = app_cfg->salt,
					.raw_key = key_256,
				},
			},
			.icv_length = DOCA_IPSEC_ICV_LENGTH_16,
			.sn_attr.sn_initial = 0,
			.direction = dir,
		},
	};

	if (dir == DOCA_IPSEC_DIRECTION_INGRESS_DECRYPT) {
		sa_create.sa_attrs.ingress.antireplay_enable = 1;
		sa_create.sa_attrs.ingress.replay_win_sz = DOCA_IPSEC_REPLAY_WIN_SIZE_128;
	} else if (dir == DOCA_IPSEC_DIRECTION_EGRESS_ENCRYPT) {
		sa_create.sa_attrs.egress.sn_inc_enable = 1;
	}

	/* Enqueue IPsec job */
	doca_error_t result = doca_workq_submit(app_cfg->doca_workq, &sa_create.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit ipsec job: %s", doca_get_error_string(result));
		exit(-1);
	}

	/* Wait for job completion */
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	struct doca_event event = { 0 };
	while ((result = doca_workq_progress_retrieve(app_cfg->doca_workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve job: %s", doca_get_error_string(result));
		exit(-1);
	}
	
	/* if job succeed event.result.ptr will point to the new created sa object */
	return event.result.ptr;
}

doca_error_t
destroy_ipsec_sa(
	struct random_spi_gw_config *app_cfg, 
	struct doca_ipsec_sa *sa)
{
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


void create_encrypt_obj(
	struct random_spi_gw_config *app_cfg,
	uint32_t ipsec_idx,
	uint16_t egress_port_id,
	uint8_t *key_256)
{
	// Submits an SA-create job to the HW and awaits the resulting object handle
	app_cfg->connections[ipsec_idx].encrypt_sa = create_security_assoc(
		app_cfg, key_256, DOCA_IPSEC_DIRECTION_EGRESS_ENCRYPT);

	struct doca_flow_shared_resource_cfg cfg = {
		.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS,
		.crypto_cfg = {
			.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP,
			.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT,
			.reformat_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP,
			.net_type = DOCA_FLOW_CRYPTO_NET_TUNNEL,
			.header_type = DOCA_FLOW_CRYPTO_HEADER_NONE, // Ignored for NET_TUNNEL
			.reformat_data_sz = sizeof(struct eth_ipv6_tunnel_ipsec_hdr),
			// reformat_data[] below
			.reformat_icv_sz = DOCA_FLOW_CRYPTO_ICV_DEFAULT,
			.security_ctx = app_cfg->connections[ipsec_idx].encrypt_sa,
			.fwd = {
				.type = DOCA_FLOW_FWD_PORT,
				.port_id = egress_port_id,
			},
		},
	};

	assert(sizeof(struct eth_ipv6_tunnel_ipsec_hdr) <= DOCA_FLOW_CRYPTO_REFORMAT_LEN_MAX);
	
	*(struct eth_ipv6_tunnel_ipsec_hdr *)cfg.crypto_cfg.reformat_data = app_cfg->encap_hdr;

	doca_error_t result = doca_flow_shared_resource_cfg(
		DOCA_FLOW_SHARED_RESOURCE_CRYPTO, ipsec_idx, &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to cfg shared ipsec object: %s", doca_get_error_string(result));
		exit(-1);
	}

	result = doca_flow_shared_resources_bind(
		DOCA_FLOW_SHARED_RESOURCE_CRYPTO, &ipsec_idx, 1, app_cfg->pf.port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind shared ipsec object to port: %s", doca_get_error_string(result));
		exit(-1);
	}
}

void create_decrypt_obj(
	struct random_spi_gw_config *app_cfg,
	uint32_t ipsec_idx,
	uint8_t *key_256)
{
	// Submits an SA-create job to the HW and awaits the resulting object handle
	app_cfg->connections[ipsec_idx].decrypt_sa = create_security_assoc(
		app_cfg, key_256, DOCA_IPSEC_DIRECTION_INGRESS_DECRYPT);

	struct doca_flow_shared_resource_cfg cfg = {
		.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS,
		.crypto_cfg = {
			.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP,
			.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT,
			.reformat_type = DOCA_FLOW_CRYPTO_REFORMAT_DECAP,
			.net_type = DOCA_FLOW_CRYPTO_NET_TUNNEL,
			.header_type = DOCA_FLOW_CRYPTO_HEADER_NONE, // Ignored for NET_TUNNEL
			.reformat_data_sz = sizeof(struct rte_ether_hdr),
			// reformat_data[] below
			.reformat_icv_sz = DOCA_FLOW_CRYPTO_ICV_DEFAULT,
			.security_ctx = app_cfg->connections[ipsec_idx].decrypt_sa,
			.fwd = {
				.type = DOCA_FLOW_FWD_PIPE,
				.next_pipe = app_cfg->syndrome_pipe,
			},
		},
	};

	assert(sizeof(struct rte_ether_hdr) <= DOCA_FLOW_CRYPTO_REFORMAT_LEN_MAX);

	*(struct rte_ether_hdr *)cfg.crypto_cfg.reformat_data = app_cfg->decap_eth_hdr;

	doca_error_t result = doca_flow_shared_resource_cfg(
		DOCA_FLOW_SHARED_RESOURCE_CRYPTO, ipsec_idx, &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to cfg shared ipsec object: %s", doca_get_error_string(result));
		exit(-1);
	}

	result = doca_flow_shared_resources_bind(
		DOCA_FLOW_SHARED_RESOURCE_CRYPTO, &ipsec_idx, 1, app_cfg->pf.port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind shared ipsec object to port: %s", doca_get_error_string(result));
		exit(-1);
	}
}

struct doca_flow_pipe *
create_empty_root_pipe(
	struct doca_flow_port *port,
	enum doca_flow_pipe_domain domain,
	struct doca_flow_pipe *next_pipe)
{
	const char *pipe_name = "DUMMY_ROOT_PIPE";
	struct doca_flow_match match = {};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = next_pipe,
	};
	struct doca_flow_pipe_cfg pipe_cfg = {
		.attr = {
			.name = pipe_name,
			.domain = domain,
			.is_root = true,
			.nb_flows = 1,
			.type = DOCA_FLOW_PIPE_BASIC,
		},
		.port = port,
		.match = &match,
	};
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}

	struct doca_flow_pipe_entry *entry = NULL;
	result = doca_flow_pipe_add_entry(0, pipe,
		&match, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe entry: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}

	result = doca_flow_entries_process(port, 0, TIMEOUT_USEC, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process %s pipe entries: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}
	return pipe;
}

struct doca_flow_pipe *create_encrypt_pipe(
	const struct random_spi_gw_config *app_cfg)
{
	const char *pipe_name = "ENCRYPT_PIPE";

	struct doca_flow_match match_mask = {
		.meta.random = UINT16_MAX,
	};

	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
	};

	struct doca_flow_actions crypto_action = {
		.security = {
			.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP,
			.crypto_id = UINT32_MAX, // specified by each entry
		},
	};
	struct doca_flow_actions *actions[] = { &crypto_action };

	// fwd handled by shared_crypto action
	struct doca_flow_fwd miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = pipe_name,
			.nb_actions = 1,
			.nb_flows = app_cfg->num_spi,
			.type = DOCA_FLOW_PIPE_HASH,
			.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS,
		},
		.port = app_cfg->pf.port,
		.match_mask = &match_mask,
		.monitor = &mon,
		.actions = actions,
		.actions_masks = actions,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t result = doca_flow_pipe_create(&cfg, NULL, &miss, &pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}

	for (uint32_t i = 0; i < app_cfg->num_spi; i++) {
		crypto_action.security.crypto_id = app_cfg->connections[i].ipsec_idx;
		
		struct doca_flow_pipe_entry *entry = NULL;
		result = doca_flow_pipe_hash_add_entry(0, pipe,
			i, &crypto_action, &mon, NULL, DOCA_FLOW_NO_WAIT, NULL, &entry);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create %s pipe entry %d: %s", 
				pipe_name, i, doca_get_error_string(result));
			exit(-1);
		}

		if ((i % QUEUE_DEPTH) == (QUEUE_DEPTH - 1)) {
			result = doca_flow_entries_process(app_cfg->pf.port, 0, TIMEOUT_USEC, QUEUE_DEPTH);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failed to process %s pipe entries: %s", pipe_name, doca_get_error_string(result));
				exit(-1);
			}
		}
	}

	result = doca_flow_entries_process(app_cfg->pf.port, 0, TIMEOUT_USEC, app_cfg->num_spi % QUEUE_DEPTH);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process %s pipe entries: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}
	return pipe;
}

struct doca_flow_pipe *create_decrypt_pipe(
	const struct random_spi_gw_config *app_cfg)
{
	const char *pipe_name = "DECRYPT_PIPE";

	struct doca_flow_match match = {
		.outer = {
//			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
		},
		.tun = {
			.type = DOCA_FLOW_TUN_ESP,
			.esp_spi = UINT32_MAX,
		},
	};

	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
	};

	struct doca_flow_actions crypto_action = {
		.security = {
			.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP,
			.crypto_id = UINT32_MAX,
		},
	};
	struct doca_flow_actions *actions[] = { &crypto_action };

	// fwd handled by shared_crypto action
	struct doca_flow_fwd miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = pipe_name,
			.nb_actions = 1,
			.type = DOCA_FLOW_PIPE_BASIC,
			.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS,
		},
		.port = app_cfg->pf.port,
		.match = &match,
		.monitor = &mon,
		.actions = actions,
		.actions_masks = actions,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t result = doca_flow_pipe_create(&cfg, NULL, &miss, &pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}

	for (uint32_t i = 0; i < app_cfg->num_spi; i++) {
		match.tun.esp_spi = app_cfg->connections[i].spi;
		crypto_action.security.crypto_id = app_cfg->connections[i].ipsec_idx + app_cfg->num_spi;
		
		struct doca_flow_pipe_entry *entry = NULL;
		result = doca_flow_pipe_add_entry(0, pipe,
			&match, &crypto_action, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &entry);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create %s pipe entry %d: %s", 
				pipe_name, i, doca_get_error_string(result));
			exit(-1);
		}
	}

	result = doca_flow_entries_process(app_cfg->pf.port, 0, TIMEOUT_USEC, app_cfg->num_spi);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process %s pipe entries: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}
	return pipe;
}


struct doca_flow_pipe *create_decrypt_syndrome_pipe(
	const struct random_spi_gw_config *app_cfg,
	uint32_t dest_port_id)
{
	const char *pipe_name = "DECRYPT_SYNDROME_PIPE";

	struct doca_flow_match match = {};
	struct doca_flow_match match_mask = {
		.meta = {
			.ipsec_syndrome = UINT8_MAX, // decrypt-syndrome bits
			.u32 = { UINT32_MAX, UINT32_MAX }, // anti-replay syndrome bits
		},
	};

	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
	};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = dest_port_id,
	};
	struct doca_flow_fwd miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = pipe_name,
			.type = DOCA_FLOW_PIPE_BASIC,
		},
		.port = app_cfg->pf.port,
		.match = &match,
		.match_mask = &match_mask,
		.monitor = &mon,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t result = doca_flow_pipe_create(&cfg, &fwd, &miss, &pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}

	struct doca_flow_pipe_entry *entry = NULL;
	result = doca_flow_pipe_add_entry(0, pipe,
		&match, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe entry: %s", 
			pipe_name, doca_get_error_string(result));
	}

	result = doca_flow_entries_process(app_cfg->pf.port, 0, TIMEOUT_USEC, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process %s pipe entries: %s", pipe_name, doca_get_error_string(result));
		exit(-1);
	}
	return pipe;
}

doca_error_t register_argp_params()
{
	// TODO: argp for dmac, num_spi, etc.
	return DOCA_SUCCESS;
}

static void random_spi_gw_init_crypto_objs(
	struct random_spi_gw_config *app_cfg)
{
	for (int i=0; i<app_cfg->num_spi; i++) {
		uint8_t key_256[KEY_LEN_BYTES];
		idx_to_key256(i, key_256);
		create_encrypt_obj(app_cfg, i, 0, key_256);
		create_decrypt_obj(app_cfg, i + app_cfg->num_spi, key_256);
	}
}

static doca_error_t random_spi_gw_init_flows(
	struct random_spi_gw_config *app_cfg)
{
	DOCA_LOG_INFO("Creating Syndrome Pipe");
	app_cfg->syndrome_pipe = create_decrypt_syndrome_pipe(app_cfg, 1);

	DOCA_LOG_INFO("Creating %d Crypto Objects", app_cfg->num_spi);
	random_spi_gw_init_crypto_objs(app_cfg);

	DOCA_LOG_INFO("Creating Decrypt Pipe");
	app_cfg->decrypt_pipe = create_decrypt_pipe(app_cfg);

	DOCA_LOG_INFO("Creating Encrypt Pipe");
	app_cfg->encrypt_pipe = create_encrypt_pipe(app_cfg);

	DOCA_LOG_INFO("Creating Root Pipes");
	create_empty_root_pipe(app_cfg->pf.port, DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS, app_cfg->decrypt_pipe);
	create_empty_root_pipe(app_cfg->pf.port, DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS, app_cfg->encrypt_pipe);
	create_empty_root_pipe(app_cfg->pf.port, DOCA_FLOW_PIPE_DOMAIN_DEFAULT, app_cfg->syndrome_pipe);

	return DOCA_SUCCESS;
}

/*
 * IPsec Security Gateway application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	doca_error_t result;
	int ret, nb_ports = 2;
	int exit_status = EXIT_SUCCESS;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = nb_ports,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 2,
		.port_config.enable_mbuf_metadata = true,
		.port_config.isolated_mode = true,
		.reserve_main_thread = true,
	};
	struct random_spi_gw_config app_cfg = {
		.dpdk_config = &dpdk_config,
		.nb_cores = DEFAULT_NB_CORES,
		.num_spi = 128,
		.pf = {
			.dev_pci_dbdf = "17:00.0",
		}
	};

	char cores_str[10];
	char *eal_param[5] = {"", "-a", "00:00.0", "-l", ""};

	/* Register a logger backend */
	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	force_quit = false;

	/* Init ARGP interface and start parsing cmdline/json arguments */
	result = doca_argp_init("roce_ipsec_security_gw", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	result = register_argp_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register application params: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	app_cfg.connections = calloc(app_cfg.num_spi, sizeof(struct connection));
	if (!app_cfg.connections) {
		DOCA_LOG_ERR("Failed to allocate %d connection object caches", app_cfg.num_spi);
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}

	snprintf(cores_str, sizeof(cores_str), "0-%d", app_cfg.nb_cores - 1);
	eal_param[4] = cores_str;
	ret = rte_eal_init(5, eal_param);
	if (ret < 0) {
		DOCA_LOG_ERR("EAL initialization failed");
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}

	result = random_spi_gw_init_devices(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA devices: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}

	/* Update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	// Cannot query mac address until DPDK ports are probed
	rte_eth_macaddr_get(0, &app_cfg.encap_hdr.eth.src_addr);
	// TODO: get dmac from argp
	rte_ether_unformat_addr("b8:3f:d2:ba:65:ee", &app_cfg.encap_hdr.eth.dst_addr);
	// TODO: encap IP addr, decap mac addr

	result = random_spi_gw_ipsec_ctx_create(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create encrypt sa object: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_cleanup;
	}

	result = random_spi_gw_init_doca_flow(&app_cfg, dpdk_config.port_config.nb_queues);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow");
		exit_status = EXIT_FAILURE;
		goto ipsec_ctx_cleanup;
	}
	
	result = random_spi_gw_init_flows(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow Pipes and/or Crypto Objects");
		exit_status = EXIT_FAILURE;
		goto doca_flow_cleanup;
	}

	DOCA_LOG_INFO("Initialization complete; hit CTRL-C to quit.");
	while (!force_quit) {
		sleep(1);
	}
	DOCA_LOG_INFO("All done; shutting down");

doca_flow_cleanup:
	/* Flow cleanup */
	doca_flow_port_stop(app_cfg.pf.port);
	doca_flow_destroy();

	/* Destroy rules SAs */
	random_spi_gw_destroy_sas(&app_cfg);

ipsec_ctx_cleanup:
	random_spi_gw_ipsec_ctx_destroy(&app_cfg);

dpdk_cleanup:
	/* DPDK cleanup */
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_destroy:
	dpdk_fini();

argp_destroy:
	/* ARGP cleanup */
	doca_argp_destroy();

	return exit_status;
}
