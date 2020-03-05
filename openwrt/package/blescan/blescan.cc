#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define EIR_NAME_SHORT      0x08 /* shortened local name */
#define EIR_NAME_COMPLETE   0x09 /* complete local name */

#define DEBUG
#ifdef DEBUG
struct stats {
	unsigned int bad_event;
	unsigned int directed;
	unsigned int other;
	unsigned int bad_report;
	unsigned int len_mismatch;
	unsigned int multi;
} stats;

#define INCR_STAT(stat) stats.stat++
void dump_stats() {
	fprintf(stderr, "stats\n"
			"  bad_event:    %u\n"
			"  directed:     %u\n"
			"  other:        %u\n"
			"  bad_report:   %u\n"
			"  len_mismatch: %u\n"
			"  multi:        %u\n",
		stats.bad_event,
		stats.directed,
		stats.other,
		stats.bad_report,
		stats.len_mismatch,
		stats.multi);
}
#else
#define INCR_STAT(stat)
void dump_stats() {}
#endif

static volatile int signal_received = 0;

void sig_handler(int sig) {
	if (sig == SIGINT)
		signal_received = 1;
}

void eir_parse_name(uint8_t *eir, size_t eir_len,
    char* buf, size_t buf_len) {
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* check for the end of EIR */
		if (field_len == 0) {
			break;
		}

		if(offset + field_len > eir_len) {
			goto failed;
		}

		switch(eir[1]) {
			case EIR_NAME_SHORT:
				//printf("EIR_NAME_SHORT\n");
				name_len = field_len -1;
				if (name_len > buf_len) {
					goto failed;
				}
				memcpy(buf, &eir[2], name_len);
				return;
			case EIR_NAME_COMPLETE:
				//printf("EIR_NAME_LONG\n");
				name_len = field_len - 1;
				if (name_len > buf_len) {
					goto failed;
				}
				memcpy(buf, &eir[2], name_len);
				return;
			}
		offset += field_len + 1;
		eir += field_len + 1;
	}
	failed:
		snprintf(buf, buf_len, "(unknown)");
	}

void parse_advertising_report(evt_le_meta_event *meta, unsigned char len) {
	le_advertising_info *info = (le_advertising_info *) (meta->data + 1);
	// 1-byte le meta subevent type +
	// 1-byte # of advertising reports +
	// 1-byte advertisement type +
	// 1-byte addr type +
	// 6-byte addr +
	// 1-byte data length +
	// 1-byte rssi
	if (len < 12 ||
	    len < 12 + info->length) {
		INCR_STAT(bad_report);
		return;
	}
	if (len != 12 + info->length)
		INCR_STAT(len_mismatch);

	// get # of advertising reports - this is always 1 on any h/w I've seen
	unsigned int num_reports = meta->data[0];
	if (num_reports > 1)
		INCR_STAT(multi);

	// skip random address advertisements, if not static address
	// cf BT spec 4.2, Vol 6 (LE controller), section 1.3.2
#define STATIC_ADDRESS ( 3 << 6 )
	if (info->bdaddr_type != LE_RANDOM_ADDRESS ||
	    ((info->bdaddr.b[5] & STATIC_ADDRESS) == STATIC_ADDRESS)) {
		char addr[18];
		char name[30];
		char rssi;

		memset(name, 0, sizeof(name));
		ba2str(&info->bdaddr, addr);
		rssi = info->data[info->length];
		eir_parse_name(info->data, info->length, name, sizeof(name) - 1);
		printf("%s \"%s\" %d\n", addr, name, rssi);
	}
}

	int print_advertising_devices(int dev_handle) {
		struct hci_filter nf, of;
		struct sigaction sa;
		socklen_t olen;
		int len;

		olen = sizeof(of);

		if (getsockopt(dev_handle, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
			fprintf(stderr, "Could not get socket options (%d)\n", errno);
			return -1;
		}

		hci_filter_clear(&nf);
		hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
		hci_filter_set_event(EVT_LE_META_EVENT, &nf);

		if (setsockopt(dev_handle, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
			fprintf(stderr, "Could not set socket options (%d)\n", errno);
			return -1;
		}

		memset(&sa, 0, sizeof(sa));
		sa.sa_flags = SA_NOCLDSTOP;
		sa.sa_handler = sig_handler;
		sigaction(SIGINT, &sa, NULL);

		while (1) {
			unsigned char buf[HCI_MAX_EVENT_SIZE];

			if ((len = read(dev_handle, buf, sizeof(buf))) < 0) {
				if (signal_received) {
					len = 0;
					break;
				}

				if (errno == EAGAIN || errno == EINTR)
					continue;

				fprintf(stderr, "read error (%d)\n", errno);
				break;
			}

			// 1-byte HCI packet type [==hci event] +
			// 1-byte HCI event type [==le meta event] +
			// 1-byte len event data +
			// 1-byte LE meta subevent type
			if (len < 4 ||
			    buf[0] != HCI_EVENT_PKT ||
			    buf[1] != EVT_LE_META_EVENT ||
			    buf[2] != len - 3) {
				INCR_STAT(bad_event);
				continue;
			}

			len -= 3;
			evt_le_meta_event *meta = (evt_le_meta_event *) (buf + 3);
			switch (meta->subevent) {
			case 0x0b:  // direct advertising report
				INCR_STAT(directed);
				/* fall-through */
			case EVT_LE_ADVERTISING_REPORT:
				parse_advertising_report(meta, len);
				break;
			default:
				INCR_STAT(other);
			}
		}
		setsockopt(dev_handle, SOL_HCI, HCI_FILTER, &of, sizeof(of));

		if (len < 0) {
			return -1;
		}

		return 0;
	}

	void usage(char* str) {
		fprintf(stderr,
		"Usage: %s "
		"[-i || --scan_interval] "
		"[-w || --scan_window] "
		"\n", str);
	    exit(EXIT_SUCCESS);
	}

	int main(int argc, char**argv) {
		int dev_id, dev_handle, rc;
		int c;
		uint16_t scan_interval = 0x0010;
		uint16_t scan_window = 0x0010;

		setbuf(stdout, NULL);

		while(1) {
			static struct option long_options[] = {
                {"scan_interval", optional_argument, 0, 'i'},
                {"scan_window", optional_argument, 0, 'w'},
                {0, 0, 0, 0}
			};
			int option_index = 0;
			c = getopt_long(argc, argv, "i:w:", long_options, &option_index);
			if (-1 == c) {
				break; //detect end of the options
			}

			switch(c) {
				case 'i':
					scan_interval = strtol(optarg, NULL, 0);
					break;
				case 'w':
					scan_window = strtol(optarg, NULL, 0);
					break;
				default:
					usage(argv[0]);
			}
		}

		dev_id = hci_get_route(NULL);
		if ((dev_handle = hci_open_dev(dev_id)) < 0) {
			fprintf(stderr, "Failed to open hci device handle %d (%d)\n", dev_id, errno);
			exit(-1);
		}

		/* dev_id, uint8_t type, uint16_t interval, uint16t window, uint8_t own_type, uint8_t filter, int to */
		if (hci_le_set_scan_parameters(dev_handle, 0x01, htobs(scan_interval), htobs(scan_window), 0x01, 0x00, 1000) < 0) {
			// try again after disabling scanning
			fprintf(stderr, "Failed to set scan parameters (%d)\n", errno);
			if (hci_le_set_scan_enable(dev_handle, 0, 0, 1000) < 0 ||
			    hci_le_set_scan_parameters(dev_handle, 0x01, htobs(scan_interval),
						       htobs(scan_window), 0x01, 0x00, 1000) < 0) {
				fprintf(stderr, "failed after retry attempt\n");
				exit(-1);
			}
		}

		/* dev_id, enabled, filter_dup, timeout (ms) */
		if (hci_le_set_scan_enable(dev_handle, 1, 0, 1000) < 0) {
			fprintf(stderr, "Failed to enable hci le scan (%d)\n", errno);
			exit(-1);
		}

		rc = print_advertising_devices(dev_handle);

		/* Disable scanning */
		if (hci_le_set_scan_enable(dev_handle, 0, 0, 1000) < 0)
			fprintf(stderr, "Failed to disable the le scan (%d)\n", errno);

		if (hci_close_dev(dev_handle) < 0)
			fprintf(stderr, "Failed to close the dev handle %d (%d)\n", dev_handle, errno);

		fprintf(stderr, "Exiting (%d)\n", rc);
		dump_stats();
		return rc;
	}
