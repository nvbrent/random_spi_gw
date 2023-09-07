#pragma once

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ipsec.h>

#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_ipsec.h>

#include <dpdk_utils.h>

struct eth_ipv6_tunnel_ipsec_hdr {
	// encapped Ethernet header contents.
	struct rte_ether_hdr eth;

	// encapped IPv6 header contents.
	// no extension-header supported.
	struct rte_ipv6_hdr ip;

	// encapped IPSec ESP header contents.
	// omits sn/iv; include them below.
	struct rte_esp_hdr esp;

	// IPsec anti-replay sequence number.
	// populated by HW offload.
	rte_be32_t sn;

	// IPsec initialization vector, 8/16 bytes.
	// populated by HW offload.
	uint8_t iv[16];
};

struct connection {
	uint32_t encrypt_ipsec_idx;
	uint32_t decrypt_ipsec_idx;
	rte_be32_t spi;
	struct doca_ipsec_sa *encrypt_sa;
	struct doca_ipsec_sa *decrypt_sa;
	struct doca_flow_pipe_entry *encrypt_pipe_entry;
	struct doca_flow_pipe_entry *decrypt_pipe_entry;
};

struct random_spi_gw_config {
	struct application_dpdk_config *dpdk_config;
	uint32_t nb_cores;

    uint32_t num_spi;
	
	struct eth_ipv6_tunnel_ipsec_hdr encap_hdr;
	struct rte_ether_hdr decap_eth_hdr;

	// Probe a single PF with some number of VF representors
	struct PF {
		uint32_t port_id;
		char dev_pci_dbdf[DOCA_DEVINFO_PCI_ADDR_SIZE];
		struct doca_dev *dev;
		struct doca_flow_port *port;
	} pf;

	struct VF {
		uint32_t port_id;
	} vf;

	uint32_t salt;

	struct doca_ipsec *ipsec_ctx;			/* DOCA IPSEC context */
	struct doca_workq *doca_workq;			/* DOCA IPSEC workq */
	struct doca_ctx *doca_ctx;			/* DOCA IPSEC as context */

	struct doca_flow_pipe *uplink_root_pipe;
	struct doca_flow_pipe *encrypt_pipe;
	struct doca_flow_pipe *decrypt_pipe;
	struct doca_flow_pipe *syndrome_pipe;

	struct connection *connections;
};

doca_error_t random_spi_gw_ipsec_ctx_create(struct random_spi_gw_config *app_cfg);

doca_error_t random_spi_gw_ipsec_ctx_destroy(const struct random_spi_gw_config *app_cfg);

doca_error_t random_spi_gw_init_devices(struct random_spi_gw_config *app_cfg);

void random_spi_gw_destroy_sas(struct random_spi_gw_config *app_cfg);