#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('random-spi-gw', 'C', 'CPP',
	version: '0.0.1',
	default_options: ['buildtype=debug']
)

APP_NAME = meson.project_name()

cpp_args = ['-std=c++11']

add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

dependency_libdpdk = dependency('libdpdk', required : false)
if not dependency_libdpdk.found()
	error('Please set PKG_CONFIG_PATH to DPDK packages path, for further instructions please refer to the DOCA Reference Applications guide')
endif
app_dependencies = [dependency_libdpdk]
app_dependencies += dependency('json-c', required : true)
app_dependencies += dependency('threads', required : true)
app_dependencies += dependency('doca', required : true)

doca_home = '/opt/mellanox/doca'
common_dir_path = doca_home + '/applications/common/src'

app_inc_dirs = [include_directories(doca_home, common_dir_path, 'src')]

app_srcs = [
	'src/random_spi_gw.c',
	'src/random_spi_gw_dev.c',
	'src/random_spi_gw_program_args.c',
	# DOCA-provided utilities:
	common_dir_path + '/dpdk_utils.c',
	common_dir_path + '/offload_rules.c',
	common_dir_path + '/utils.c',
    doca_home + '/samples/common.c',
]

executable(APP_NAME, app_srcs,
	cpp_args : cpp_args,
	dependencies : app_dependencies,
	include_directories : app_inc_dirs)
