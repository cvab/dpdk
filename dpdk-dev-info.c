/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_string_fns.h>
#include <rte_metrics.h>

#include <rte_eventdev.h>
#include <rte_cryptodev.h>

/* Maximum long option length for option parsing. */
#define MAX_LONG_OPT_SZ 64
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define MAX_STRING_LEN 256

/**< mask of enabled ports */
static uint32_t enabled_dev_mask;
/**< Enable stats. */
static uint32_t enable_stats;
/**< Enable xstats. */
static uint32_t enable_xstats;
/**< Enable collectd format*/
static uint32_t enable_collectd_format;
/**< FD to send collectd format messages to STDOUT*/
static int stdout_fd;
/**< Host id process is running on */
static char host_id[MAX_LONG_OPT_SZ];
/**< Enable metrics. */
static uint32_t enable_metrics;
/**< Enable stats reset. */
static uint32_t reset_stats;
/**< Enable xstats reset. */
static uint32_t reset_xstats;
/**< Enable device. */
static uint32_t eth_dev, crypto_dev, event_dev;
/**< Enable displaying xstat name. */
static uint32_t enable_xstats_name;
static char *xstats_name;
/**< Enable config dump. */
static uint32_t enable_dump;

/**< Enable xstats by ids. */
#define MAX_NB_XSTATS_IDS 1024
static uint32_t nb_xstats_ids;
static uint64_t xstats_ids[MAX_NB_XSTATS_IDS];

/**< display usage */
static void
dev_info_usage(const char *prgname)
{
	printf("%s [EAL options] -- -d DEVMASK\n"
		"  -c for cryptodev stats/dev info \n"
		"  -e for ethernet stats/dev info\n"
		"  -E for eventdev stats/dump\n"
		"  -d DEVICEMASK: hexadecimal bitmask of devices to retrieve stats for\n"
		"  --stats: to display port/device statistics, enabled by default\n"
		"  --xstats: to display extended port/device statistics, disabled by "
			"default\n"
		"  --metrics: to display derived metrics of the ports, disabled by "
			"default\n"
		"  --xstats-name NAME: to display single xstat id by NAME\n"
		"  --xstats-ids IDLIST: to display xstat values by id. "
			"The argument is comma-separated list of xstat ids to print out.\n"
		"  --stats-reset: to reset port/device statistics\n"
		"  --xstats-reset: to reset port/device extended statistics\n"
		"  --collectd-format: to print statistics to STDOUT in expected by collectd format\n"
		"  --host-id STRING: host id used to identify the system process is running on\n"
		"  --dump: to display port/device configuration dump, disabled by default\n",
		prgname);
}

/*
 * Parse the devmask provided at run time.
 */
static int
parse_devmask(const char *devmask)
{
	char *end = NULL;
	unsigned long dm;

	errno = 0;

	/* parse hexadecimal string */
	dm = strtoul(devmask, &end, 16);
	if ((devmask[0] == '\0') || (end == NULL) || (*end != '\0') ||
		(errno != 0)) {
		printf("%s ERROR parsing the device mask\n", __func__);
		return -1;
	}

	if (dm == 0)
		return -1;

	return dm;

}

/*
 * Parse ids value list into array
 */
static int
parse_xstats_ids(char *list, uint64_t *ids, int limit) {
	int length;
	char *token;
	char *ctx = NULL;
	char *endptr;

	length = 0;
	token = strtok_r(list, ",", &ctx);
	while (token != NULL) {
		ids[length] = strtoull(token, &endptr, 10);
		if (*endptr != '\0')
			return -EINVAL;

		length++;
		if (length >= limit)
			return -E2BIG;

		token = strtok_r(NULL, ",", &ctx);
	}

	return length;
}

static int
dev_info_preparse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int i;

	for (i = 0; i < argc; i++) {
		/* Print stats or xstats to STDOUT in collectd format */
		if (!strncmp(argv[i], "--collectd-format", MAX_LONG_OPT_SZ)) {
			enable_collectd_format = 1;
			stdout_fd = dup(STDOUT_FILENO);
			close(STDOUT_FILENO);
		}
		if (!strncmp(argv[i], "--host-id", MAX_LONG_OPT_SZ)) {
			if ((i + 1) == argc) {
				printf("Invalid host id or not specified\n");
				dev_info_usage(prgname);
				return -1;
			}
			strncpy(host_id, argv[i+1], sizeof(host_id));
		}
	}

	if (!strlen(host_id)) {
		int err = gethostname(host_id, MAX_LONG_OPT_SZ-1);

		if (err)
			strcpy(host_id, "unknown");
	}

	return 0;
}

/* Parse the argument given in the command line of the application */
static int
dev_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	static struct option long_option[] = {
		{"stats", 0, NULL, 0},
		{"stats-reset", 0, NULL, 0},
		{"xstats", 0, NULL, 0},
		{"metrics", 0, NULL, 0},
		{"xstats-reset", 0, NULL, 0},
		{"xstats-name", required_argument, NULL, 1},
		{"collectd-format", 0, NULL, 0},
		{"xstats-ids", 1, NULL, 1},
		{"host-id", 0, NULL, 0},
		{"dump", 0, NULL, 0},
		{NULL, 0, 0, 0}
	};

	if (argc == 1)
		dev_info_usage(prgname);

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "ceEd:",
			long_option, &option_index)) != EOF) {
		switch (opt) {
		/* devmask */
		case 'd':
			enabled_dev_mask = parse_devmask(optarg);
			if (enabled_dev_mask == 0) {
				printf("invalid device mask\n");
				dev_info_usage(prgname);
				return -1;
			}
			break;
		case 'c':
			crypto_dev = 1;
			break;
		case 'e':
			eth_dev = 1;
			break;
		case 'E':
			event_dev = 1;
			break;
		case 0:
			/* Print stats */
			if (!strncmp(long_option[option_index].name, "stats",
					MAX_LONG_OPT_SZ))
				enable_stats = 1;
			/* Print xstats */
			else if (!strncmp(long_option[option_index].name, "xstats",
					MAX_LONG_OPT_SZ))
				enable_xstats = 1;
			else if (!strncmp(long_option[option_index].name,
					"metrics",
					MAX_LONG_OPT_SZ))
				enable_metrics = 1;
			/* Reset stats */
			if (!strncmp(long_option[option_index].name, "stats-reset",
					MAX_LONG_OPT_SZ))
				reset_stats = 1;
			/* Reset xstats */
			else if (!strncmp(long_option[option_index].name, "xstats-reset",
					MAX_LONG_OPT_SZ))
				reset_xstats = 1;
			else if (!strncmp(long_option[option_index].name, "dump",
					MAX_LONG_OPT_SZ))
				enable_dump = 1;
			break;
		case 1:
			/* Print xstat single value given by name*/
			if (!strncmp(long_option[option_index].name,
					"xstats-name", MAX_LONG_OPT_SZ)) {
				enable_xstats_name = 1;
				xstats_name = optarg;
				printf("name:%s:%s\n",
						long_option[option_index].name,
						optarg);
			} else if (!strncmp(long_option[option_index].name,
					"xstats-ids",
					MAX_LONG_OPT_SZ))	{
				nb_xstats_ids = parse_xstats_ids(optarg,
						xstats_ids, MAX_NB_XSTATS_IDS);

				if (nb_xstats_ids <= 0) {
					printf("xstats-id list parse error.\n");
					return -1;
				}

			}
			break;
		default:
			dev_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}

static void
crypto_dev_stats_display(uint8_t dev_id)
{
	struct rte_cryptodev_stats stats;
	static const char *stats_border = "########################";

	rte_cryptodev_stats_get(dev_id, &stats);

	printf("\n  %s Cryptodev statistics for device %-2d %s\n",
		   stats_border, dev_id, stats_border);
	printf("  Enqueued count     : %-10"PRIu64"  Dequeued count     :  %-10"PRIu64"\n", 
		   stats.enqueued_count, stats.dequeued_count);
	printf("  Enqueue error count: %-10"PRIu64"  Dequeue error count:  %-10"PRIu64"\n", 
		   stats.enqueue_err_count, stats.dequeue_err_count);
	printf("  %s####################################%s\n",
		   stats_border, stats_border);
}

static void
crypto_dev_stats_clear(uint8_t dev_id)
{
	printf("\n Clearing cryptodev stats for device %d\n", dev_id);
	rte_cryptodev_stats_reset(dev_id);
	printf("\n  Cryptodev statistics for device %d cleared\n", dev_id);
}

static void
nic_stats_display(uint8_t port_id)
{
	struct rte_eth_stats stats;
	uint8_t i;

	static const char *nic_stats_border = "########################";

	rte_eth_stats_get(port_id, &stats);
	printf("\n  %s NIC statistics for port %-2d %s\n",
		   nic_stats_border, port_id, nic_stats_border);

	printf("  RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
	       "  RX-bytes:  %-10"PRIu64"\n", stats.ipackets, stats.ierrors,
	       stats.ibytes);
	printf("  RX-nombuf:  %-10"PRIu64"\n", stats.rx_nombuf);
	printf("  TX-packets: %-10"PRIu64"  TX-errors:  %-10"PRIu64
	       "  TX-bytes:  %-10"PRIu64"\n", stats.opackets, stats.oerrors,
	       stats.obytes);

	printf("\n");
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		printf("  Stats reg %2d RX-packets: %-10"PRIu64
		       "  RX-errors: %-10"PRIu64
		       "  RX-bytes: %-10"PRIu64"\n",
		       i, stats.q_ipackets[i], stats.q_errors[i], stats.q_ibytes[i]);
	}

	printf("\n");
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		printf("  Stats reg %2d TX-packets: %-10"PRIu64
		       "  TX-bytes: %-10"PRIu64"\n",
		       i, stats.q_opackets[i], stats.q_obytes[i]);
	}

	printf("  %s############################%s\n",
		   nic_stats_border, nic_stats_border);
}

static void
nic_stats_clear(uint8_t port_id)
{
	printf("\n Clearing NIC stats for port %d\n", port_id);
	rte_eth_stats_reset(port_id);
	printf("\n  NIC statistics for port %d cleared\n", port_id);
}

static void collectd_resolve_cnt_type(char *cnt_type, size_t cnt_type_len,
				      const char *cnt_name) {
	char *type_end = strrchr(cnt_name, '_');

	if ((type_end != NULL) &&
	    (strncmp(cnt_name, "rx_", strlen("rx_")) == 0)) {
		if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
			strncpy(cnt_type, "if_rx_errors", cnt_type_len);
		else if (strncmp(type_end, "_dropped", strlen("_dropped")) == 0)
			strncpy(cnt_type, "if_rx_dropped", cnt_type_len);
		else if (strncmp(type_end, "_bytes", strlen("_bytes")) == 0)
			strncpy(cnt_type, "if_rx_octets", cnt_type_len);
		else if (strncmp(type_end, "_packets", strlen("_packets")) == 0)
			strncpy(cnt_type, "if_rx_packets", cnt_type_len);
		else if (strncmp(type_end, "_placement",
				 strlen("_placement")) == 0)
			strncpy(cnt_type, "if_rx_errors", cnt_type_len);
		else if (strncmp(type_end, "_buff", strlen("_buff")) == 0)
			strncpy(cnt_type, "if_rx_errors", cnt_type_len);
		else
			/* Does not fit obvious type: use a more generic one */
			strncpy(cnt_type, "derive", cnt_type_len);
	} else if ((type_end != NULL) &&
		(strncmp(cnt_name, "tx_", strlen("tx_"))) == 0) {
		if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
			strncpy(cnt_type, "if_tx_errors", cnt_type_len);
		else if (strncmp(type_end, "_dropped", strlen("_dropped")) == 0)
			strncpy(cnt_type, "if_tx_dropped", cnt_type_len);
		else if (strncmp(type_end, "_bytes", strlen("_bytes")) == 0)
			strncpy(cnt_type, "if_tx_octets", cnt_type_len);
		else if (strncmp(type_end, "_packets", strlen("_packets")) == 0)
			strncpy(cnt_type, "if_tx_packets", cnt_type_len);
		else
			/* Does not fit obvious type: use a more generic one */
			strncpy(cnt_type, "derive", cnt_type_len);
	} else if ((type_end != NULL) &&
		   (strncmp(cnt_name, "flow_", strlen("flow_"))) == 0) {
		if (strncmp(type_end, "_filters", strlen("_filters")) == 0)
			strncpy(cnt_type, "operations", cnt_type_len);
		else if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
			strncpy(cnt_type, "errors", cnt_type_len);
		else if (strncmp(type_end, "_filters", strlen("_filters")) == 0)
			strncpy(cnt_type, "filter_result", cnt_type_len);
	} else if ((type_end != NULL) &&
		   (strncmp(cnt_name, "mac_", strlen("mac_"))) == 0) {
		if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
			strncpy(cnt_type, "errors", cnt_type_len);
	} else {
		/* Does not fit obvious type, or strrchr error: */
		/* use a more generic type */
		strncpy(cnt_type, "derive", cnt_type_len);
	}
}

static void
nic_xstats_by_name_display(uint8_t port_id, char *name)
{
	uint64_t id;

	printf("###### NIC statistics for port %-2d, statistic name '%s':\n",
			   port_id, name);

	if (rte_eth_xstats_get_id_by_name(port_id, name, &id) == 0)
		printf("%s: %"PRIu64"\n", name, id);
	else
		printf("Statistic not found...\n");

}

static void
nic_xstats_by_ids_display(uint8_t port_id, uint64_t *ids, int len)
{
	struct rte_eth_xstat_name *xstats_names;
	uint64_t *values;
	int ret, i;
	static const char *nic_stats_border = "########################";

	values = malloc(sizeof(*values) * len);
	if (values == NULL) {
		printf("Cannot allocate memory for xstats\n");
		return;
	}

	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstat names\n");
		free(values);
		return;
	}

	if (len != rte_eth_xstats_get_names_by_id(
			port_id, xstats_names, len, ids)) {
		printf("Cannot get xstat names\n");
		goto err;
	}

	printf("###### NIC extended statistics for port %-2d #########\n",
			   port_id);
	printf("%s############################\n", nic_stats_border);
	ret = rte_eth_xstats_get_by_id(port_id, ids, values, len);
	if (ret < 0 || ret > len) {
		printf("Cannot get xstats\n");
		goto err;
	}

	for (i = 0; i < len; i++)
		printf("%s: %"PRIu64"\n",
			xstats_names[i].name,
			values[i]);

	printf("%s############################\n", nic_stats_border);
err:
	free(values);
	free(xstats_names);
}

static void
nic_xstats_display(uint8_t port_id)
{
	struct rte_eth_xstat_name *xstats_names;
	uint64_t *values;
	int len, ret, i;
	static const char *nic_stats_border = "########################";

	len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
	if (len < 0) {
		printf("Cannot get xstats count\n");
		return;
	}
	values = malloc(sizeof(*values) * len);
	if (values == NULL) {
		printf("Cannot allocate memory for xstats\n");
		return;
	}

	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstat names\n");
		free(values);
		return;
	}
	if (len != rte_eth_xstats_get_names_by_id(
			port_id, xstats_names, len, NULL)) {
		printf("Cannot get xstat names\n");
		goto err;
	}

	printf("###### NIC extended statistics for port %-2d #########\n",
			   port_id);
	printf("%s############################\n",
			   nic_stats_border);
	ret = rte_eth_xstats_get_by_id(port_id, NULL, values, len);
	if (ret < 0 || ret > len) {
		printf("Cannot get xstats\n");
		goto err;
	}

	for (i = 0; i < len; i++) {
		if (enable_collectd_format) {
			char counter_type[MAX_STRING_LEN];
			char buf[MAX_STRING_LEN];

			collectd_resolve_cnt_type(counter_type,
						  sizeof(counter_type),
						  xstats_names[i].name);
			sprintf(buf, "PUTVAL %s/dpdkstat-port.%u/%s-%s N:%"
				PRIu64"\n", host_id, port_id, counter_type,
				xstats_names[i].name, values[i]);
			write(stdout_fd, buf, strlen(buf));
		} else {
			printf("%s: %"PRIu64"\n", xstats_names[i].name,
					values[i]);
		}
	}

	printf("%s############################\n",
			   nic_stats_border);
err:
	free(values);
	free(xstats_names);
}

static void
nic_xstats_clear(uint8_t port_id)
{
	printf("\n Clearing NIC xstats for port %d\n", port_id);
	rte_eth_xstats_reset(port_id);
	printf("\n  NIC extended statistics for port %d cleared\n", port_id);
}

static void
metrics_display(int port_id)
{
	struct rte_metric_value *metrics;
	struct rte_metric_name *names;
	int len, ret;
	static const char *nic_stats_border = "########################";

	len = rte_metrics_get_names(NULL, 0);
	if (len < 0) {
		printf("Cannot get metrics count\n");
		return;
	}
	if (len == 0) {
		printf("No metrics to display (none have been registered)\n");
		return;
	}

	metrics = rte_malloc("dev_info_metrics",
		sizeof(struct rte_metric_value) * len, 0);
	if (metrics == NULL) {
		printf("Cannot allocate memory for metrics\n");
		return;
	}

	names =  rte_malloc(NULL, sizeof(struct rte_metric_name) * len, 0);
	if (names == NULL) {
		printf("Cannot allocate memory for metrcis names\n");
		rte_free(metrics);
		return;
	}

	if (len != rte_metrics_get_names(names, len)) {
		printf("Cannot get metrics names\n");
		rte_free(metrics);
		rte_free(names);
		return;
	}

	if (port_id == RTE_METRICS_GLOBAL)
		printf("###### Non port specific metrics  #########\n");
	else
		printf("###### metrics for port %-2d #########\n", port_id);
	printf("%s############################\n", nic_stats_border);
	ret = rte_metrics_get_values(port_id, metrics, len);
	if (ret < 0 || ret > len) {
		printf("Cannot get metrics values\n");
		rte_free(metrics);
		rte_free(names);
		return;
	}

	int i;
	for (i = 0; i < len; i++)
		printf("%s: %"PRIu64"\n", names[i].name, metrics[i].value);

	printf("%s############################\n", nic_stats_border);
	rte_free(metrics);
	rte_free(names);
}

int
main(int argc, char **argv)
{
	int ret;
	int i;
	char c_flag[] = "-c1";
	char n_flag[] = "-n4";
	char mp_flag[] = "--proc-type=secondary";
	char *argp[argc + 3];
	uint8_t nb_devs;

	/* preparse app arguments */
	ret = dev_info_preparse_args(argc, argv);
	if (ret < 0) {
		printf("Failed to parse arguments\n");
		return -1;
	}

	argp[0] = argv[0];
	argp[1] = c_flag;
	argp[2] = n_flag;
	argp[3] = mp_flag;

	for (i = 1; i < argc; i++)
		argp[i + 3] = argv[i];

	argc += 3;

	ret = rte_eal_init(argc, argp);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	argc -= ret;
	argv += (ret - 3);

	if (!rte_eal_primary_proc_alive(NULL))
		rte_exit(EXIT_FAILURE, "No primary DPDK process is running.\n");

	/* parse app arguments */
	ret = dev_info_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid argument\n");

	if (enable_dump) {
		if (event_dev) {
			struct rte_event_dev_info info;   
			nb_devs = rte_event_dev_count();
			if (nb_devs == 0)
				rte_exit(EXIT_FAILURE, "No Eventdevs - bye\n");
			for (i = 0; i < nb_devs; i++) {  
				if (enabled_dev_mask & (1 << i)) {  
					rte_event_dev_info_get(i, &info);
					{ 
						static const char *info_border = "########################";
						printf("\n  %s Eventdev info for device %-2d %s\n",
							   info_border, i, info_border);
						if (info.dev) 
							printf("\n  Device name: %s  numa_node: %d\n", 
										info.dev->name, info.dev->numa_node);
						printf("  Driver name: %c%s%c   min deq timeout(ns) : %-10"PRIu32" max deq timeout(ns) :  %-10"PRIu32"\n", 
							   34,info.driver_name,34, info.min_dequeue_timeout_ns, info.max_dequeue_timeout_ns);
						printf("  max event qs : %-10"PRIu32" max eventq flows : %-10"PRIu32" max eventq prio levels : %-10"PRIu32"\n", 
							   info.max_event_queues, info.max_event_queue_flows, info.max_event_queue_priority_levels);
						printf("  max event prio levels : %-10"PRIu32" max event ports : %-10"PRIu32" max events : %-10"PRIu32"\n", 
							   info.max_event_priority_levels, info.max_event_ports, info.max_num_events);
						printf("  max ev port deq depth : %-10"PRIu32" max ev port enq depth : %-10"PRIu32" eventdev cap: %-10"PRIu32"\n", 
							   info.max_event_port_dequeue_depth, info.max_event_port_enqueue_depth, info.event_dev_cap);
						printf("  %s####################################%s\n",
							   info_border, info_border);

					}	
					rte_event_dev_dump(i, stdout); 
				}
			}
		} else if (crypto_dev) { 
			struct rte_cryptodev_info info;   
			nb_devs = rte_cryptodev_count();
			if (nb_devs == 0)
				rte_exit(EXIT_FAILURE, "No Cryptodevs - bye\n");
			for (i = 0; i < nb_devs; i++) {  
				if (enabled_dev_mask & (1 << i)) {  
					rte_cryptodev_info_get(i, &info);
					{ 
						static const char *info_border = "########################";
						printf("\n  %s Cryptodev info for device %-2d %s\n",
							   info_border, i, info_border);
						/*if (info.pci_dev) 
							printf("\n  Device name: %s  numa_node: %d\n", 
										((info.pci_dev)->device).name, info.pci_dev->device.numa_node); */
						printf("  Driver name: %c%s%c Driver id : %-5"PRIu8"  fflags : 0x%04lX   mode : %-10"PRIu32"\n", 
							   34,info.driver_name,34, info.driver_id, info.feature_flags, info.capabilities->op);
						printf("  max no qpairs : %-10"PRIu32" max nb sessions : %-5"PRIu32"  max nb session per qp : %-5"PRIu32"\n", 
							   info.max_nb_queue_pairs, info.sym.max_nb_sessions, info.sym.max_nb_sessions_per_qp);
						printf("  %s##############################%s\n",
							   info_border, info_border);
					}	
				}
			}
		} else if (eth_dev) { 
			struct rte_eth_dev_info info;
			nb_devs = rte_eth_dev_count();
			if (nb_devs == 0)
				rte_exit(EXIT_FAILURE, "No Ethernet devs - bye\n");
			for (i = 0; i < nb_devs; i++) {  
				if (enabled_dev_mask & (1 << i)) {  
					rte_eth_dev_info_get(i, &info);
					{ 
						static const char *info_border = "###################################";
						printf("\n  %s EthDev info for device %-2d %s\n",
							   info_border, i, info_border);
						/*if (info.pci_dev) 
							printf("\n  Device name: %s  numa_node: %d\n", 
										((info.pci_dev)->device).name, info.pci_dev->device.numa_node); */
						printf("  Driver name: %c%s%c if index : %-5"PRIu8"  min rx bufsize : %-5"PRIu32"   max rx pktlen : %-10"PRIu32"\n", 
							   34,info.driver_name,34, info.if_index, info.min_rx_bufsize, info.max_rx_pktlen);
						printf("  max rxqs : %-10"PRIu32" max txqs : %-5"PRIu32"  nb rxqs : %-5"PRIu32" nb txqs : %-5"PRIu32"\n", 
							   info.max_rx_queues, info.max_tx_queues, info.nb_rx_queues, info.nb_tx_queues);
						printf("  max vfs : %-10"PRIu32" max vmdq pools : %-5"PRIu32"  rx offload : %-5"PRIu32" tx offload : %-5"PRIu32"\n", 
							   info.max_vfs, info.max_vmdq_pools, info.rx_offload_capa, info.tx_offload_capa);
						printf("  redir tblsize : %-10"PRIu16" hash key size : %-5"PRIu16"  rss offload/type mask : %-5"PRIu64" speed cap : %-5"PRIu32"\n", 
							   info.reta_size, info.hash_key_size, info.flow_type_rss_offloads, info.speed_capa);
						printf("  rx drop en : %-2"PRIu32" rx free thresh : %-5"PRIu32"  rx deferred start : %-5"PRIu32"\n", 
							   info.default_rxconf.rx_drop_en, info.default_rxconf.rx_free_thresh, info.default_rxconf.rx_deferred_start);
						printf("  rx pthresh : %-5"PRIu32"  rx hthresh : %-5"PRIu32" rx wthresh : %-5"PRIu32"\n", 
							   info.default_rxconf.rx_thresh.pthresh, info.default_rxconf.rx_thresh.hthresh, info.default_rxconf.rx_thresh.wthresh); 
						printf("  tx_rs thresh : %-5"PRIu32" tx free thresh : %-5"PRIu32"  txq flags : %-5"PRIu32" tx deferred start: %3u\n", 
							   info.default_txconf.tx_rs_thresh, info.default_txconf.tx_free_thresh, info.default_txconf.txq_flags, info.default_txconf.tx_deferred_start);
						printf("  tx pthresh : %-5"PRIu32"  tx hthresh : %-5"PRIu32" tx wthresh : %-5"PRIu32"\n", 
							   info.default_txconf.tx_thresh.pthresh, info.default_txconf.tx_thresh.hthresh, info.default_txconf.tx_thresh.wthresh); 
						printf("  rx desc: nb max : %-5"PRIu32" nb min : %-5"PRIu32"  nb align : %-5"PRIu32" nb seg max : %-5"PRIu32" nb mtu seg max :  %-5"PRIu32"\n", 
							   info.rx_desc_lim.nb_max, info.rx_desc_lim.nb_min, info.rx_desc_lim.nb_align, info.rx_desc_lim.nb_seg_max, info.rx_desc_lim.nb_mtu_seg_max);
						printf("  tx desc: nb max : %-5"PRIu32" nb min : %-5"PRIu32"  nb align : %-5"PRIu32" nb seg max : %-5"PRIu32" nb mtu seg max :  %-5"PRIu32"\n", 
							   info.tx_desc_lim.nb_max, info.tx_desc_lim.nb_min, info.tx_desc_lim.nb_align, info.tx_desc_lim.nb_seg_max, info.tx_desc_lim.nb_mtu_seg_max);
						printf("  %s###########################%s\n",
							   info_border, info_border);
					}	
				}
			}
		} else { 
			rte_exit(EXIT_FAILURE, "Device dump apis supported only for Eventdev\n");
		}  
		return 0;
	}

	if (eth_dev) { 
		nb_devs = rte_eth_dev_count();
		if (nb_devs == 0)
			rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

		/* If no port mask was specified*/
		if (enabled_dev_mask == 0)
			enabled_dev_mask = 0xffff;

		for (i = 0; i < nb_devs; i++) {
			if (enabled_dev_mask & (1 << i)) {
				if (enable_stats) 
					nic_stats_display(i); 
				else if (enable_xstats)
					nic_xstats_display(i);
				else if (reset_stats)
					nic_stats_clear(i);
				else if (reset_xstats)
					nic_xstats_clear(i);
				else if (enable_xstats_name)
					nic_xstats_by_name_display(i, xstats_name);
				else if (nb_xstats_ids > 0)
					nic_xstats_by_ids_display(i, xstats_ids,
							nb_xstats_ids);
				else if (enable_metrics)
					metrics_display(i);
			}
		}
	} 

	if (crypto_dev) { 
		nb_devs = rte_cryptodev_count();
		if (nb_devs == 0)
			rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

		/* If no dev mask was specified*/
		if (enabled_dev_mask == 0)
			enabled_dev_mask = 0xffff;

		for (i = 0; i < nb_devs; i++) {
			if (enabled_dev_mask & (1 << i)) {
				if (enable_stats || enable_xstats) 
					crypto_dev_stats_display(i); 
				else if (reset_stats || reset_xstats)
					crypto_dev_stats_clear(i);
				else if (enable_xstats_name || nb_xstats_ids || enable_metrics) { 
					printf("Cryptodev Ops not supported\n");
					dev_info_usage(argv[0]);
				} else if (reset_stats || reset_xstats) 
					rte_cryptodev_stats_reset(i); /* clear the stats */
			}
		}
	} 

	if (event_dev) { 
		nb_devs = rte_event_dev_count();
		if (nb_devs == 0)
			rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

		/* If no dev mask was specified*/
		if (enabled_dev_mask == 0)
			enabled_dev_mask = 0xffff;

		for (i = 0; i < nb_devs; i++) {
			if (enabled_dev_mask & (1 << i)) {
				if (enable_stats || enable_xstats) 
					rte_event_dev_dump(i, stdout); 
				else if (reset_stats || reset_xstats) { 
					printf("Eventdev operation not supported\n");
					dev_info_usage(argv[0]);
				}
			}
		}
	}	

	/* print port independent stats */
	if (enable_metrics)
		metrics_display(RTE_METRICS_GLOBAL);

	return 0;
}
