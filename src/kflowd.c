/*
 * kflowd.c
 *
 * Authors: Dirk Tennie <dirk@tarsal.co>
 *          Barrett Lyon <blyon@tarsal.co>
 *
 * Copyright 2024 (c) Tarsal, Inc
 *
 */

#include <stdint.h>
#include "kflowd.h"
#include "kflowd.skel.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <dlfcn.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <argp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>

/* help and usage strings */
static char title_str[] = "\e[1m  _     __ _                  _\n"
                          " | | __/ _| | _____      ____| |\n"
                          " | |/ / |_| |/ _ \\ \\ /\\ / / _` |\n"
                          " |   <|  _| | (_) \\ V  V / (_| |\n"
                          " |_|\\_\\_| |_|\\___/ \\_/\\_/ \\__,_|\e[0m  by Tarsal.co\n";

static char header_str[] = "\e[1;33mkflowd -- (c) 2024 Tarsal, Inc\e[0m\n"
                           "\e[0;33mKernel-based Process Monitoring via eBPF subsystem (" VERSION ")\e[0m\n";
static char usage_str[] =
    "Usage:\n"
    "  kflowd [-m file,socket] [-t IDLE,ACTIVE] [-e EVENTS] [-o json|json-min|table] [-v] [-c]\n"
    "         [-p dns=PROTO/PORT,...] [-p http=PROTO/PORT,...] [-u IP:PORT] [-q] [-d] [-V]\n"
    "         [-T TOKEN] [-D PROCESS], [-l] [--legend], [-h] [--help], [--version]\n"
    "  -m file,socket          Monitor only specified kernel subsystem (filesystem or sockets)\n"
    "                            (default: all, option omitted!)\n"
    "  -t IDLE,ACTIVE          Timeout in seconds for idle or active network sockets until export\n"
    "                            (default: idle '15' seconds, active '1800' seconds)\n"
    "  -e EVENTS               Max number of filesystem events per aggregated record until export\n"
    "                            (default: disabled, '1': no aggregation)\n"
    "  -o json                 Json output with formatting (default)\n"
    "     json-min             Json output with minimal formatting \n"
    "     table                Tabular output with limited keys and no UDP output\n"
    "  -v                      Version of executable files identified by installed package\n"
    "                            (supported only for rpm- and deb-based package management)\n"
    "  -c                      Checksum hashes of MD5 and SHA256 calculated for executables\n"
    "  -p dns=PROTO/PORT,...   Port(s) examined for decoding of DNS application protocol\n"
    "                            (default: 'dns=udp/53,tcp/53', disabled: 'dns=off')\n"
    "  -p http=PROTO/PORT,...  Port(s) examined for decoding of HTTP application protocol\n"
    "                            (default: 'http=tcp/80', disabled: 'http=off')\n"
    "  -u IP:PORT,...          UDP server(s) IPv4 or IPv6 address to send json output to.\n"
    "                          Output also printed to stdout console unless quiet option -q or\n"
    "                            daemon mode -d specified\n"
    "  -q                      Quiet mode to suppress output to stdout console\n"
    "  -d                      Daemonize program to run in background\n"
    "  -V                      Verbose output\n"
    "                            Print eBPF load and co-re messages on start of eBPF program\n"
    "                            to stderr console\n"
    "  -T TOKEN                Token specified on host to be included in json output\n"
    "  -l, --legend            Show legend\n"
    "  -h, --help              Show help\n"
    "      --version           Show version\n"
    "  -D PROCESS              Debug\n"
    "                            Print ebpf kernel log messages of process or expiration queue to\n"
    "                            kernel trace pipe (any process: '*', with quotes!, queue: 'q')\n"
    "                            Use command:\n"
    "                              'sudo cat /sys/kernel/debug/tracing/trace_pipe'\n\n"
    "Examples:\n"
    "  sudo ./kflowd                                                           # terminal mode\n"
    "  sudo ./kflowd -m file,socket -v -c -u 1.2.3.4:2056,127.0.0.1:2057 -d    # daemon mode\n"
    "  sudo ./kflowd -m socket -v -c -u 1.2.3.4:2056 -V -D '*'                 # debug mode\n"
    "  sudo ./kflowd --legend                                                  # show legend\n"
    "  sudo ./kflowd --version                                                 # show version\n\n";
static char doc_str[] =
    "kflowd provides an eBPF program running in Kernel context and its control application running\n"
    "in userspace.\n"
    "The eBPF program traces kernel functions to monitor processes based on filesystem, TCP and UDP\n"
    "networking events and optionally DNS and HTTP application messages via plugins.\n"
    "Events are aggregated and submitted into a ringbuffer where they are polled by the userspace\n"
    "control application and converted into messages in json output format.\n"
    "Messages are printed to stdout console and can be sent via UDP protocol to specified hosts.\n\n";

static void usage(char *msg) {
    fprintf(stdout, "%s", header_str);
    if (strlen(msg)) {
        fprintf(stdout, "%s", usage_str);
        fprintf(stdout, "\e[1;91m%s%s\e[0m\n", "Error: ", msg);
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "%s", doc_str);
    fprintf(stdout, "%s", usage_str);
    exit(EXIT_SUCCESS);
}
static bool          opt_version = false;
static struct option longopts[] = {{"legend", no_argument, NULL, 'l'},
                                   {"help", no_argument, NULL, 'h'},
                                   {"version", no_argument, (int *)&opt_version, 1},
                                   {0, 0, 0, 0}};

/* define globals */
static char              *cache_user[CACHE_ENTRIES_MAX] = {0};
static char              *cache_group[CACHE_ENTRIES_MAX] = {0};
static char              *cache_device[CACHE_ENTRIES_MAX] = {0};
static char              *cache_mount[CACHE_ENTRIES_MAX] = {0};
static char              *cache_interface[CACHE_ENTRIES_MAX] = {0};
static bool               cache_user_update = true;
static bool               cache_group_update = true;
static bool               cache_device_mount_update = true;
static bool               cache_version_update = false;
static bool               cache_interface_update = true;
static time_t             cache_user_mtime = 0;
static time_t             cache_group_mtime = 0;
static time_t             cache_device_mount_mtime = 0;
static time_t             cache_version_mtime = 0;
static uint64_t           record_count = 0;
static struct utsname     utsn = {0};
static char               hostip[INET6_ADDRSTRLEN] = {0};
static struct kflowd_bpf *skel;
static struct bpf_map    *map_xf = NULL;
static struct timespec    spec_start;
static volatile bool      running = false;

static struct CONFIG {
    int   monitor;
    bool  mode_daemon;
    int   agg_events_max;
    int   agg_idle_timeout;
    int   agg_active_timeout;
    bool  xfile_version;
    bool  file_checksum;
    int   output_type;
    bool  output_udp;
    char  output_udp_host[UDP_SERVER_MAX][INET6_ADDRSTRLEN];
    short output_udp_port[UDP_SERVER_MAX];
    int   output_udp_family[UDP_SERVER_MAX];
    int   output_udp_num;
    bool  output_udp_quiet;
    short app_proto[APP_MAX][APP_PORT_MAX];
    short app_port[APP_MAX][APP_PORT_MAX];
    int   app_port_num[APP_MAX];
    bool  verbose;
    char  token[TOKEN_LEN_MAX];
    char  debug[DBG_LEN_MAX];
} config = {0};

static struct JSON_KEY jkey[] = {
    {I_INFO_SEQUENCE_NUMBER, {"InfoSequenceNumber"}, "Increasing sequence number for each message"},
    {I_INFO_TIMESTAMP, {"InfoTimestamp"}, "Message timestamp in UTC datetime format with nanoseconds"},
    {I_INFO_MONITOR, {"InfoMonitor"}, "Kernel subsystem monitored (filesytem, networking*)"},
    {I_INFO_HOST_NAME, {"InfoHostName"}, "Local host name"},
    {I_INFO_HOST_IP, {"InfoHostIP"}, "Local IP address"},
    {I_INFO_HOST_TOKEN, {"InfoHostToken"}, "Optional host token provided as config option"},
    {I_INFO_SYSTEM, {"InfoSystem"}, "Operating system name"},
    {I_INFO_KERNEL, {"InfoKernel", "nix_kernel", "nixKernel"}, "Kernel version of operating system"},
    {I_INFO_VERSION, {"InfoVersion"}, "Version of kflowd application"},
    {I_INFO_UPTIME, {"InfoUptime"}, "Uptime of kflowd application in seconds and nanoseconds"},
    {I_PROC_PARENT, {"ProcParent"}, "Name of parent process "},
    {I_PROC, {"Proc", "nix_process_name", "nixProcessName"}, "Name of process"},
    {I_PROC_VERSION, {"ProcVersion", "nix_process_version", "nixProcessVersion"}, "Package version of process binary"},
    {I_PROC_USER, {"ProcUser", "nix_uname", "nixUname"}, "User name of process"},
    {I_PROC_GROUP, {"ProcGroup"}, "Group name of process"},
    {I_PROC_PPID, {"ProcPPID"}, "Process ID of parent process"},
    {I_PROC_PID, {"ProcPID", "nix_pid", "nixPid"}, "Process ID"},
    {I_PROC_TID, {"ProcTID"}, "Thread ID of process"},
    {I_PROC_UID, {"ProcUID", "nix_uid", "nixUid"}, "User ID of process"},
    {I_PROC_GID, {"ProcGID"}, "Group ID of process"},
    {I_PROC_AGE, {"ProcAge"}, "Running time of process in seconds and nanoseconds"},
    {I_FILE_PATH, {"FilePath", "path", "path"}, "Directory path name of file"},
    {I_FILE, {"File", "file", "file"}, "File name"},
    {I_FILE_ORIGIN, {"FileOrigin"}, "Original file name of renamed file"},
    {I_FILE_VERSION, {"FileVersion"}, "Package version of file if available"},
    {I_FILE_MODE, {"FileMode"}, "Regular file, symbolic link or hard link"},
    {I_FILE_EVENT_COUNT, {"FileEventCount"}, "File event count"},
    {I_FILE_EVENTS, {"FileEvents", "fs_event", "fsEvent"}, "File event types and count"},
    {I_FILE_EVENTS_DURATION, {"FileEventsDuration"}, "Duration of all file events from first to last"},
    {I_FILE_INODE, {"FileInode"}, "Inode number of File"},
    {I_FILE_INODE_LINK_COUNT, {"FileInodeLinkCount"}, "Symbolic link count for inode"},
    {I_FILE_DEVICE, {"FileDevice"}, "File device id, name, mount point, file system type"},
    {I_FILE_PERMISSIONS, {"FilePermissions", "file_perm", "filePerm"}, "File read, write and executable permissions"},
    {I_FILE_USER, {"FileUser", "file_owner", "fileOwner"}, "User name of file"},
    {I_FILE_GROUP, {"FileGroup", "file_group", "fileGroup"}, "Group name of file"},
    {I_FILE_UID, {"FileUID"}, "User ID of file"},
    {I_FILE_GID, {"FileGID"}, "Group ID of file"},
    {I_FILE_SIZE, {"FileSize", "file_size", "fileSize"}, "File size in bytes"},
    {I_FILE_SIZE_CHANGE, {"FileSizeChange"}, "File size change in bytes after modification (can be negative)"},
    {I_FILE_ACCESS_TIME, {"FileAccessTime", "file_accessed", "fileAccessed"}, "Access timestamp in UTC"},
    {I_FILE_STATUS_CHANGE_TIME, {"FileStatusChangeTime"}, "Status change timestamp in UTC"},
    {I_FILE_MODIFICATION_TIME, {"FileModificationTime"}, "Modification timestamp in UTC"},
    {I_FILE_MODIFICATION_TIME_CHANGE, {"FileModificationTimeChange"}, "Elapsed seconds since last modification"},
    {I_FILE_CHECKSUM_MD5, {"FileMD5", "file_md5", "fileMD5"}, "MD5 hash checksum of file"},
    {I_FILE_CHECKSUM_SHA256, {"FileSHA256", "file_sha256", "fileSha256"}, "SHA256 hash checksum of file"},
    {I_SOCK_PROTOCOL, {"SockProtocol"}, "Socket protocol of either TCP or UDP"},
    {I_SOCK_ROLE, {"SockRole"}, "Socket role of either client or server"},
    {I_SOCK_STATE, {"SockState"}, "TCP or UDP state of socket"},
    {I_SOCK_FAMILY, {"SockFamily"}, "Socket Family of either AF_INET or AF_INET6"},
    {I_SOCK_LOCAL_IP, {"SockLocalIP"}, "Local IPv4 or IPv6 address of socket"},
    {I_SOCK_LOCAL_PORT, {"SockLocalPort"}, "Local TCP or UDP port of socket"},
    {I_SOCK_REMOTE_IP, {"SockRemoteIP"}, "Remote IPv4 or IPv6 address of socket"},
    {I_SOCK_REMOTE_PORT, {"SockRemotePort"}, "Remote TCP or UDP port of socket"},
    {I_SOCK_TX_INTERFACE, {"SockTxInterface"}, "Egress interface index, name and mac for tx packets on socket"},
    {I_SOCK_TX_DATA_PACKETS, {"SockTxDataPackets"}, "Transmitted data packets on socket"},
    {I_SOCK_TX_PACKETS, {"SockTxPackets"}, "Transmitted packets on socket"},
    {I_SOCK_TX_PACKETS_RETRANS, {"SockTxPacketsRetrans"}, "Re-transmitted packets on TCP socket"},
    {I_SOCK_TX_PACKETS_DUPS, {"SockTxPacketsDups"}, "Duplicate-selective-acked (DSACK) tx packets on TCP socket"},
    {I_SOCK_TX_FLAGS, {"SockTxFlags"}, "Transmitted TCP flags and counts on socket"},
    {I_SOCK_TX_DURATION, {"SockTxDuration"}, "Duration from first to last tx packet on socket"},
    {I_SOCK_TX_BYTES, {"SockTxBytes"}, "Transmitted data bytes on socket"},
    {I_SOCK_TX_BYTES_ACKED, {"SockTxBytesAcked"}, "Transmitted data bytes acked on TCP socket"},
    {I_SOCK_TX_BYTES_RETRANS, {"SockTxBytesRetrans"}, "Re-transmitted data bytes on TCP socket"},
    {I_SOCK_TX_RTO, {"SockTxRTO"}, "Retransmission timeout for tx packet on socket"},
    {I_SOCK_RX_INTERFACE, {"SockRxInterface"}, "Ingress interface index, name and mac for rx packets on socket"},
    {I_SOCK_RX_DATA_PACKETS, {"SockRxDataPackets"}, "Received data packets on socket"},
    {I_SOCK_RX_PACKETS, {"SockRxPackets"}, "Received packets on socket after defragmentation"},
    {I_SOCK_RX_PACKETS_QUEUED, {"SockRxPacketsQueued"}, "Received packets in socket rx queue"},
    {I_SOCK_RX_PACKETS_DROP, {"SockRxPacketsDrop"}, "Received packets dropped from socket rx queue"},
    {I_SOCK_RX_PACKETS_REORDER, {"SockRxPacketsReorder"}, "Received packets re-ordered on TCP socket"},
    {I_SOCK_RX_PACKETS_FRAG, {"SockRxPacketsFrag"}, "Received fragmented packets on TCP socket"},
    {I_SOCK_RX_FLAGS, {"SockRxFlags"}, "Received TCP flags and counts on socket"},
    {I_SOCK_RX_DURATION, {"SockRxDuration"}, "Duration from first to last rx packet on socket"},
    {I_SOCK_RX_BYTES, {"SockRxBytes"}, "Received data bytes on socket"},
    {I_SOCK_RX_TTL, {"SockRxTTL"}, "Time-to-live for rx packet on socket"},
    {I_SOCK_RTT, {"SockRTT"}, "Average round-trip-time of TCP socket"},
    {I_SOCK_AGE, {"SockAge"}, "Socket lifetime in seconds and nanoseconds"},
    {I_APP, {"App"}, "Application name DNS or HTTP"},
    {I_APP_TX_DNS, {"AppTxDns"}, "Messages transmitted by DNS application layer"},
    {I_APP_RX_DNS, {"AppRxDns"}, "Messages received by DNS application layer"},
    {I_APP_TX_HTTP, {"AppTxHttp"}, "Messages transmitted by HTTP application layer"},
    {I_APP_RX_HTTP, {"AppRxHttp"}, "Messages received by HTTP application layer"}};

static struct JSON_SUB_KEY jsubkeys[] = {
    {I_FILE_EVENTS,
     {{"CREATE", "File created"},
      {"OPEN", "File opened"},
      {"OPEN_EXEC", "Executable file opened"},
      {"ACCESS", "File accessed"},
      {"ATTRIB", "File attribute changed"},
      {"MODIFY", "File modified"},
      {"CLOSE_NOWRITE", "File closed without write"},
      {"CLOSE_WRITE", "File closed with write"},
      {"MOVED_FROM", "File moved or renamed from original name"},
      {"MOVED_TO", "File moved or renamed to new name"},
      {"DELETE", "File deleted"}}},
    {I_SOCK_RX_FLAGS,
     {{"SYN", "TCP synchronization flag "},
      {"ACK", "TCP acknowledgement flag"},
      {"PSH", "TCP push flag"},
      {"FIN", "TCP finish flag"},
      {"RST", "TCP reset flag"},
      {"URG", "TCP urgent flag"}}},
    {I_APP_TX_DNS,
     {{"_Timestamp", "Relative timestamp when DNS message transmitted"},
      {"TransactionId", "DNS Transaction ID"},
      {"OpCode", "DNS Operation Code as QUERY, IQUERY or STATUS"},
      {"Flags", "DNS flag combination of QR, AA, TC, RD and RA flags"},
      {"ResponseCode", "DNS Response Code as NOERROR, FORMERROR, SERVFAIL, NXDOMAIN"},
      {"AnswerCount", "DNS Answer Count"},
      {"ResourceRecords", "DNS Resource Records with Type, Name, TTL, Class, Data"}}},
    {I_APP_RX_DNS,
     {{"_Timestamp", "Relative timestamp when DNS message received"},
      {"TransactionId", "DNS Transaction ID"},
      {"OpCode", "DNS Operation Code as Standard Query, Inverse Query or Status"},
      {"Flags", "DNS flag combination of QR, AA, TC, RD and RA flags"},
      {"ResponseCode", "DNS Response Code as NOERROR, FORMERR, SERVFAIL, NXDOMAIN"},
      {"AnswerCount", "DNS Answer Count"},
      {"ResourceRecords", "DNS Resource Records with Type, Name, TTL, Class, Data"}}},
    {I_APP_TX_HTTP,
     {{"_Timestamp", "Relative timestamp when HTTP message transmitted"},
      {"_Method", "HTTP request method like GET, POST, ..."},
      {"_URL", "HTTP request URL"},
      {"_Version", "HTTP protocol version"},
      {"_Status", "HTTP response status code"},
      {"_Reason", "HTTP response reason phrase"},
      {"[Header]", "HTTP standard and non-standard headers"},
      {"_Body", "HTTP message body"}}},
    {I_APP_RX_HTTP,
     {{"_Timestamp", "Relative timestamp when HTTP message received"},
      {"_Method", "HTTP request method like GET, POST, ..."},
      {"_URL", "HTTP request URL"},
      {"_Version", "HTTP protocol version"},
      {"_Status", "HTTP response status code"},
      {"_Reason", "HTTP response reason phrase"},
      {"[Header]", "HTTP standard and non-standard headers"},
      {"_Body", "HTTP message body"}}}};

static struct FS_PERM fsperm[] = {
    {I_USER_READ, USER_READ, 'r'},   {I_USER_WRITE, USER_WRITE, 'w'},   {I_USER_EXE, USER_EXE, 'x'},
    {I_GROUP_READ, GROUP_READ, 'r'}, {I_GROUP_WRITE, GROUP_WRITE, 'w'}, {I_GROUP_EXE, GROUP_EXE, 'x'},
    {I_OTHER_READ, OTHER_READ, 'r'}, {I_OTHER_WRITE, OTHER_WRITE, 'w'}, {I_OTHER_EXE, OTHER_EXE, 'x'}};

/* static function prototypes */
static int   udp_send_msg(char *, struct CONFIG *);
static char *mkjson(enum MKJSON_CONTAINER_TYPE, int, ...);
static char *mkjson_prettify(const char *, char *);

/* plugin function definitions */
typedef int                    plugin_dns_func(char *, int, struct APP_MSG_DNS *);
typedef int                    plugin_http_func(char *, int, struct APP_MSG_HTTP *);
typedef int                    plugin_virus_func(int, const char *, const char *, char *);
typedef int                    plugin_vuln_func(struct bpf_map *, int *, char *, bool, char *);
typedef int                    plugin_device_func(char **, char **);
typedef int                    plugin_interface_func(char **);
typedef int                    plugin_user_group_func(int, char **);
static plugin_dns_func        *plugin_dns_decode;
static plugin_http_func       *plugin_http_decode;
static plugin_virus_func      *plugin_virus_get_checksum;
static plugin_vuln_func       *plugin_vuln_version_cache;
static plugin_device_func     *plugin_device_cache;
static plugin_interface_func  *plugin_interface_cache;
static plugin_user_group_func *plugin_user_group_cache;
static void                   *plugin_handle;

/* handle signal */
static void sig_handler() {
    skel->data->monitor = MONITOR_NONE;
    running = false;
}

/* print legend */
static void legend(void) {
    int cntk;
    int cntk_sk;
    int cntsk;
    int nkeys;
    int nkeys_sk;
    int nskeys = 0;
    fprintf(stdout, "%s", header_str);
    nkeys = sizeof(jkey) / sizeof(struct JSON_KEY);
    nkeys_sk = sizeof(jsubkeys) / sizeof(struct JSON_SUB_KEY);

    /* count subkeys and print all keys with subkeys */
    for (cntk = 0; cntk < nkeys; cntk++)
        for (cntk_sk = 0; cntk_sk < nkeys_sk; cntk_sk++)
            if (jsubkeys[cntk_sk].index == jkey[cntk].index)
                for (cntsk = 0; cntsk < JSON_SUB_KEY_MAX; cntsk++)
                    if (jsubkeys[cntk_sk].sub[cntsk].jkey[0])
                        nskeys++;
    fprintf(stdout, "Legend (%u keys, %u subkeys):\n", nkeys, nskeys);
    for (cntk = 0; cntk < nkeys; cntk++) {
        fprintf(stdout, "  %-26s  %s\n", jkey[cntk].jtypekey[0], jkey[cntk].jlegend);
        for (cntk_sk = 0; cntk_sk < nkeys_sk; cntk_sk++)
            if (jsubkeys[cntk_sk].index == jkey[cntk].index)
                for (cntsk = 0; cntsk < JSON_SUB_KEY_MAX; cntsk++)
                    if (jsubkeys[cntk_sk].sub[cntsk].jkey[0])
                        fprintf(stdout, "   └─ %-23s %s\n", jsubkeys[cntk_sk].sub[cntsk].jkey,
                                jsubkeys[cntk_sk].sub[cntsk].jlegend);
    }
    exit(EXIT_SUCCESS);
}

/* print libbpf debug messages */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !config.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

/* callback event handler for ringbuffer records */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct RECORD      *r = data;
    struct RECORD_SOCK *rs = NULL;
    struct RECORD_FS   *rf = NULL;
    struct timespec     spec;
    struct tm          *tm;
    struct XFILES       xf_proc = {0};
    struct XFILES       xf_file = {0};
    char                dur[DATETIME_LEN_MAX] = {0};
    char                ts[DATETIME_LEN_MAX / 2];
    char                tsl[DATETIME_LEN_MAX];
    char                tsa[DATETIME_LEN_MAX];
    char                tsc[DATETIME_LEN_MAX];
    char                tsm[DATETIME_LEN_MAX];
    char                ts1[DATETIME_LEN_MAX];
    char                ts2[DATETIME_LEN_MAX];
    char                rcomm[TASK_COMM_LEN] = {0};
    char                lcomm[TASK_COMM_LEN + TASK_COMM_SHORT_LEN + 2] = {0};
    char                filename[FILENAME_LEN_MAX] = {0};
    char               *pfilename;
    char                filepath[DEV_NAME_LEN_MAX + FILEPATH_LEN_MAX] = {0};
    char               *pfilepath;
    char                localip[INET6_ADDRSTRLEN] = {0};
    char                remoteip[INET6_ADDRSTRLEN] = {0};
    char                md5digest[MD5_DIGEST_STR_LEN + 1] = {0};
    char               *md5 = md5digest;
    char                sha256digest[SHA256_DIGEST_STR_LEN + 1] = {0};
    char               *sha256 = sha256digest;
    char                mode[MODE_LEN_MAX];
    uint8_t             flags = 0;
    bool                is_moved_to = false;
    bool                is_hashed = false;
    long                time_sec;
    int                 events = 0;
    struct APP_MSG     *app_msg = NULL;
    int                 ofs = 0;
    char               *json_obj[JSON_OBJ_MAX] = {0};
    char                json_msg[JSON_OUT_LEN_MAX] = {0};
    char                json_msg_full[JSON_OUT_LEN_MAX] = {0};
    char               *json_out;
    int                 len;
    int                 cntf;
    int                 cnth;
    int                 cntm;
    int                 cntj;
    int                 cnts = 0;
    int                 cntp = 0;
    int                 cnta = 0;

    /* unused */
    (void)ctx;
    (void)data_sz;

    /* increase record count */
    record_count++;

    /* get local time */
    clock_gettime(CLOCK_REALTIME, &spec);
    tm = gmtime(&spec.tv_sec);
    strftime(ts, sizeof(ts), "%a, %b %d %Y %H:%M:%S", tm);
    snprintf(tsl, sizeof(tsl), "%s.%09lu UTC", ts, spec.tv_nsec);

    /* get duration */
    if (r->ts > r->ts_first)
        snprintf(dur, sizeof(dur), "%.03f", (r->ts - r->ts_first) / 1e9);

    /* get version of process */
    char ign[] = ":[]";
    if (config.xfile_version) {
        if ((ofs = strcspn(r->comm, ign)) != (int)strlen(r->comm))
            strncpy(rcomm, r->comm, ofs);
        bpf_map__lookup_elem(map_xf, rcomm[0] ? rcomm : r->comm, TASK_COMM_LEN, &xf_proc, sizeof(struct XFILES), 0);
    }

    // clang-format off
    /* build json objects with mkjson */
    /* info */
    clock_gettime(CLOCK_REALTIME, &spec);
    snprintf(ts1, sizeof(ts1), "%.09f",
             (spec.tv_sec - spec_start.tv_sec) + (spec.tv_nsec - spec_start.tv_nsec) / 1e9);
    json_obj[J_INFO] = mkjson(MKJ_OBJ, 10,
        J_LLUINT, JKEY(I_INFO_SEQUENCE_NUMBER), record_count,
        J_STRING, JKEY(I_INFO_TIMESTAMP), tsl,
        J_STRING, JKEY(I_INFO_MONITOR), r->type == RECORD_TYPE_FILE ? "filesystem" : "socket",
        J_STRING, JKEY(I_INFO_HOST_NAME), utsn.nodename,
        J_STRING, JKEY(I_INFO_HOST_IP), hostip,
        config.token[0] ?  J_STRING : J_IGN_STRING, JKEY(I_INFO_HOST_TOKEN), config.token,
        J_STRING, JKEY(I_INFO_SYSTEM), utsn.sysname,
        J_STRING, JKEY(I_INFO_KERNEL), utsn.release,
        J_STRING, JKEY(I_INFO_VERSION), "kflowd-" VERSION,
        J_TIMESTAMP, JKEY(I_INFO_UPTIME), ts1);

    /* proc */
    if (!strncmp(r->proc, r->comm, MIN(strlen(r->proc), strlen(r->comm))))
        snprintf(lcomm, sizeof(lcomm), "%s%s", r->comm, xf_proc.truncated ? "~" : "");
    else
        snprintf(lcomm, sizeof(lcomm), "%s/%s%s", r->comm, r->proc, xf_proc.truncated ? "~" : "");

    snprintf(ts1, sizeof(ts1), "%.09f", r->age / 1e9);
    json_obj[J_PROC] = mkjson(MKJ_OBJ, 11,
        J_STRING, JKEY(I_PROC_PARENT), r->comm_parent,
        J_STRING, JKEY(I_PROC), lcomm,
        config.xfile_version ? J_STRING : J_IGN_STRING, JKEY(I_PROC_VERSION), xf_proc.version ? xf_proc.version : "",
        J_STRING, JKEY(I_PROC_USER), cache_user[r->uid] ? cache_user[r->uid] : "",
        J_STRING, JKEY(I_PROC_GROUP), cache_group[r->gid] ? cache_group[r->gid] : "",
        J_UINT, JKEY(I_PROC_PPID), r->ppid,
        J_UINT, JKEY(I_PROC_PID), r->pid,
        J_UINT, JKEY(I_PROC_TID), r->tid,
        J_UINT, JKEY(I_PROC_UID), r->uid,
        J_UINT, JKEY(I_PROC_GID), r->gid,
        J_TIMESTAMP, JKEY(I_PROC_AGE), r->age ? ts1 : "0");

    /* sock */
    if ((config.monitor & MONITOR_SOCK) && r->type == RECORD_TYPE_SOCK) {
        rs = (struct RECORD_SOCK *)r;
        inet_ntop(rs->family, rs->laddr, localip, INET6_ADDRSTRLEN);
        inet_ntop(rs->family, rs->raddr, remoteip, INET6_ADDRSTRLEN);

        json_obj[J_SOCK] = mkjson(MKJ_OBJ, 8,
            J_STRING, JKEY(I_SOCK_PROTOCOL), rs->proto == IPPROTO_TCP ? "TCP" : "UDP",
            J_STRING, JKEY(I_SOCK_ROLE), rs->role == ROLE_TCP_SERVER || rs->role == ROLE_UDP_SERVER ? "SERVER" : "CLIENT",
            J_STRING, JKEY(I_SOCK_STATE), rs->proto == IPPROTO_TCP ? tcp_state_table[rs->state > 0 ? rs->state : 0]
                                            : (rs->state == UDP_ESTABLISHED ? "UDP_ESTABLISHED" : "UDP_CLOSE"),
            J_STRING, JKEY(I_SOCK_FAMILY), rs->family == AF_INET ? "AF_INET" : "AF_INET6",
            J_STRING, JKEY(I_SOCK_LOCAL_IP), localip,
            J_UINT, JKEY(I_SOCK_LOCAL_PORT), rs->lport,
            J_STRING, JKEY(I_SOCK_REMOTE_IP), remoteip,
            J_UINT, JKEY(I_SOCK_REMOTE_PORT), rs->rport);

        /* sock tx */
        if (rs->tx_packets) {
            char tx_flags[TCP_FLAGS_LEN_MAX] = {0};
            if(rs->proto == IPPROTO_TCP) {
                snprintf(tx_flags, sizeof(tx_flags), "{");
                for (cnts = 0; cnts < SOCK_FLAGS_MAX; ++cnts) {
                    if (!rs->tx_flags[cnts])
                        break;
                    flags = rs->tx_flags[cnts];
                    len = strlen(tx_flags);
                    snprintf(tx_flags + len, sizeof(tx_flags) - len, "\"");
                    for (cntf = 0; cntf < TCP_FLAGS_MAX; cntf++)
                        if (tcp_flags[cntf].id & flags)  {
                            len = strlen(tx_flags);
                            snprintf(tx_flags + len, sizeof(tx_flags) - len,  "%s-", tcp_flags[cntf].flag);
                        }
                    len = strlen(tx_flags);
                    snprintf(tx_flags + (len - 1), sizeof(tx_flags) - (len - 1), "\": %u, ", rs->tx_event[cnts]);
                }
                len = strlen(tx_flags);
                if(len>2)
                    snprintf(tx_flags + (len - 2), sizeof(tx_flags) - (len - 2), "}");
                else
                    snprintf(tx_flags + len , sizeof(tx_flags) - len, "}");
            }

            snprintf(ts1, sizeof(ts1), "%.09f", (rs->tx_ts - rs->tx_ts_first) / 1e9);
            json_obj[J_SOCK_TX] = mkjson(MKJ_OBJ, 11,
                J_STRING, JKEY(I_SOCK_TX_INTERFACE), cache_interface[rs->tx_ifindex] ? cache_interface[rs->tx_ifindex] : "",
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_TX_DATA_PACKETS), rs->tx_data_packets,
                J_UINT, JKEY(I_SOCK_TX_PACKETS), rs->tx_packets,
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_TX_PACKETS_RETRANS), rs->tx_packets_retrans,
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_TX_PACKETS_DUPS), rs->tx_packets_dups,
                rs->proto == IPPROTO_TCP ? J_JSON : J_IGN_JSON, JKEY(I_SOCK_TX_FLAGS), tx_flags[0] ? tx_flags : "{}",
                J_TIMESTAMP, JKEY(I_SOCK_TX_DURATION), rs->tx_ts - rs->tx_ts_first ? ts1 : "0",
                J_LLUINT, JKEY(I_SOCK_TX_BYTES), rs->tx_bytes,
                rs->proto == IPPROTO_TCP ? J_LLUINT : J_IGN_LLUINT, JKEY(I_SOCK_TX_BYTES_ACKED), rs->tx_bytes_acked,
                rs->proto == IPPROTO_TCP ? J_LLUINT : J_IGN_LLUINT, JKEY(I_SOCK_TX_BYTES_RETRANS), rs->tx_bytes_retrans,
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_TX_RTO), rs->tx_rto);
        }
        /* sock rx */
        if (rs->rx_packets) {
            char rx_flags[TCP_FLAGS_LEN_MAX] = {0};
            if(rs->proto == IPPROTO_TCP) {
                snprintf(rx_flags, sizeof(rx_flags), "{");
                for (cnts = 0; cnts < SOCK_FLAGS_MAX; ++cnts) {
                    if (!rs->rx_flags[cnts])
                        break;
                    flags = rs->rx_flags[cnts];
                    len = strlen(rx_flags);
                    snprintf(rx_flags + len, sizeof(rx_flags) - len, "\"");
                    for (cntf = 0; cntf < TCP_FLAGS_MAX; cntf++)
                        if (tcp_flags[cntf].id & flags)  {
                            len = strlen(rx_flags);
                            snprintf(rx_flags + len, sizeof(rx_flags) - len,  "%s-", tcp_flags[cntf].flag);
                        }
                    len = strlen(rx_flags);
                    snprintf(rx_flags + (len - 1), sizeof(rx_flags) - (len - 1), "\": %u, ", rs->rx_event[cnts]);
                }
                len = strlen(rx_flags);
                if(len > 2)
                    snprintf(rx_flags + (len - 2), sizeof(rx_flags) - (len - 2), "}");
                else
                    snprintf(rx_flags + len, sizeof(rx_flags) - len, "}");
            }

            snprintf(ts1, sizeof(ts1), "%.09f", (rs->rx_ts - rs->rx_ts_first) / 1e9);
            if(rs->proto == IPPROTO_TCP)
                snprintf(ts2, sizeof(ts2), "%.09f", rs->rtt / 1e9);
            json_obj[J_SOCK_RX] = mkjson(MKJ_OBJ, 12,
                J_STRING, JKEY(I_SOCK_RX_INTERFACE), cache_interface[rs->rx_ifindex] ? cache_interface[rs->rx_ifindex] : "",
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_RX_DATA_PACKETS), rs->rx_data_packets,
                J_UINT, JKEY(I_SOCK_RX_PACKETS), rs->rx_packets,
                J_UINT, JKEY(I_SOCK_RX_PACKETS_QUEUED), rs->rx_packets_queued,
                J_UINT, JKEY(I_SOCK_RX_PACKETS_DROP), rs->rx_packets_drop,
                rs->proto == IPPROTO_TCP ? J_UINT : J_IGN_UINT, JKEY(I_SOCK_RX_PACKETS_REORDER), rs->rx_packets_reorder,
                J_UINT, JKEY(I_SOCK_RX_PACKETS_FRAG), rs->rx_packets_frag,
                rs->proto == IPPROTO_TCP ? J_JSON : J_IGN_JSON, JKEY(I_SOCK_RX_FLAGS), rx_flags[0] ? rx_flags : "{}",
                J_TIMESTAMP, JKEY(I_SOCK_RX_DURATION), rs->rx_ts - rs->rx_ts_first ? ts1 : "0",
                J_LLUINT, JKEY(I_SOCK_RX_BYTES), rs->rx_bytes,
                J_UINT, JKEY(I_SOCK_RX_TTL), rs->rx_ttl,
                rs->proto == IPPROTO_TCP ? J_TIMESTAMP : J_IGN_TIMESTAMP, JKEY(I_SOCK_RTT), rs->rtt ? ts2 : "0");
        }
        snprintf(ts1, sizeof(ts1), "%.09f", (r->ts - r->ts_first) / 1e9);
        json_obj[J_SOCK_AGE] = mkjson(MKJ_OBJ, 1, J_TIMESTAMP, JKEY(I_SOCK_AGE), r->ts - r->ts_first ? ts1 : "0");

        /* app */
        app_msg = (struct APP_MSG *)&rs->app_msg;
        if (app_msg->cnt && ((app_msg->type == APP_DNS && plugin_dns_decode) ||
                             (app_msg->type == APP_HTTP && plugin_http_decode))) {
            char                *app_tx_msg[APP_MSG_MAX] = {0};
            char                *app_rx_msg[APP_MSG_MAX] = {0};
            int                  app_tx_msg_cnt = 0;
            int                  app_rx_msg_cnt = 0;
            char                *msg = NULL;

            /* decode first tx and then rx messages */
            for (cntm = 0; cntm < app_msg->cnt * 2; cntm++) {
                struct APP_MSG_DNS   dns = {0};
                struct APP_MSG_HTTP  http = {0};
                int mc = app_msg->cnt;
                int idx = cntm % mc;
                if ((app_msg->isrx[idx] && cntm < mc) || (!app_msg->isrx[idx] && cntm >= mc))
                    continue;
                ofs = (rs->proto == IPPROTO_TCP ? 2 : 0); /* for dns over tcp omit first 2 bytes contaiing length */
                if (app_msg->type == APP_DNS && !plugin_dns_decode(app_msg->data[idx] + ofs, app_msg->len[idx], &dns)) {
                    char dns_flags[DNS_FLAGS_LEN_MAX] = {0};
                    char dns_rr[DNS_RDATA_MAX*2*(DNS_QTYPE_DEC_LEN_MAX + DNS_QNAME_LEN_MAX + 32)] = {0};

                    if (dns.flags.qr || dns.flags.aa || dns.flags.tc || dns.flags.rd || dns.flags.ra) {
                        snprintf(dns_flags, sizeof(dns_flags), "[%s%s%s%s%s",
                                 dns.flags.qr ? "\"QR\", " : "", dns.flags.aa ? "\"AA\", " : "",
                                 dns.flags.tc ? "\"TC\", " : "", dns.flags.rd ? "\"RD\", " : "",
                                 dns.flags.ra ? "\"RA\", " : "");
                        len = strlen(dns_flags);
                        if(len > 2)
                            snprintf(dns_flags + (len - 2), sizeof(dns_flags) - (len - 2), "]");
                        else
                            snprintf(dns_flags, sizeof(dns_flags), "[]");
                    }

                    if (dns.flags.qr) {
                        snprintf(dns_rr, sizeof(dns_rr), "[");
                        for (cnta = 0; cnta < MIN(dns.ancount, DNS_RDATA_MAX); cnta++) {
                            len = strlen(dns_rr);
                            snprintf(dns_rr + len, sizeof(dns_rr) - len, "[%s], ",
                                    strlen(dns.an[cnta].rdata_dec) < (sizeof(dns_rr) - len - 8) ? dns.an[cnta].rdata_dec : "\"~\"");
                        }
                        len = strlen(dns_rr);
                        if(len > 2)
                            snprintf(dns_rr + (len - 2), sizeof(dns_rr) - (len - 2), "]");
                        else
                            snprintf(dns_rr, sizeof(dns_rr), "[]");
                    } else {
                        for (cntf = 0; cntf < DNS_QTYPE_MAX; cntf++)
                            if (dns.qtype == dns_qtypes[cntf].id)
                                break;
                        if (cntf == DNS_QTYPE_MAX)
                            snprintf(dns_rr, sizeof(dns_rr), "[[\"%u\", \"%s\"]]", dns.qtype,
                                    strlen(dns.qname + 1) < sizeof(dns_rr) ? dns.qname + 1 : "~");
                        else
                            snprintf(dns_rr, sizeof(dns_rr), "[[\"%s\", \"%s\"]]", dns_qtypes[cntf].type,
                                    strlen(dns.qname + 1) < sizeof(dns_rr) ? dns.qname + 1 : "~");
                    }
                    snprintf(ts1, sizeof(ts1), "%.09f", (app_msg->ts[idx] - r->ts_first) / 1e9);
                    msg = mkjson(MKJ_OBJ, 7,
                        J_TIMESTAMP, "_Timestamp", app_msg->ts[idx] - r->ts_first ? ts1 : "0",
                        J_UINT, "TransactionId", dns.transaction_id,
                        !dns.flags.qr ? J_STRING : J_IGN_STRING, "OpCode", dns.flags.opcode < DNS_OPCODE_MAX ?
                            dns_opcode_table[dns.flags.opcode] : "-",
                        dns.flags.qr ? J_STRING : J_IGN_STRING, "ResponseCode", dns.flags.rcode < DNS_RCODE_MAX ?
                            dns_rcode_table[dns.flags.rcode] : "-",
                        J_JSON, "Flags", dns_flags[0] ? dns_flags : "[]",
                        dns.flags.qr ? J_UINT : J_IGN_UINT, "AnswerCount", dns.ancount,
                        J_JSON, "ResourceRecords", dns_rr[0] ? dns_rr : "[]");
                } else if (app_msg->type == APP_DNS) {
                    msg = mkjson(MKJ_OBJ, 1,
                        J_STRING, "_Exception", "ERROR");
                }
                else if (app_msg->type == APP_HTTP && !plugin_http_decode(app_msg->data[idx], app_msg->len[idx], &http)) {
                    int msg_size = APP_MSG_LEN_MAX;
                    snprintf(ts1, sizeof(ts1), "%.09f", (app_msg->ts[idx] - r->ts_first) / 1e9);
                    char *msg_http = mkjson(MKJ_OBJ, 6,
                        J_TIMESTAMP, "_Timestamp", app_msg->ts[idx] - r->ts_first ? ts1 : "0",
                        strlen(http.method) ? J_STRING : J_IGN_STRING, "_Method", http.method,
                        strlen(http.url) ? J_STRING : J_IGN_STRING, "_Url", http.url,
                        strlen(http.version) ? J_STRING : J_IGN_STRING, "_Version", http.version,
                        http.status ? J_UINT : J_IGN_UINT, "_Status", http.status,
                        strlen(http.reason) ? J_STRING : J_IGN_STRING, "_Reason", http.reason);
                    msg = calloc(msg_size, sizeof(char));
                    snprintf(msg, msg_size, "%s", msg_http);
                    free(msg_http);
                    for (cnth = 0; cnth < HTTP_HEADERS_MAX; cnth++) {
                        if (!http.header_name[cnth][0])
                            break;
                        len = strlen(msg);
                        if(!cnth)
                            len -= 1;
                        if(msg_size - len - 1 > (int)strlen(http.header_name[cnth]) + (int)strlen(http.header_value[cnth]) + 32)
                            snprintf(msg + len, msg_size - len, ", \"%s\": \"%s\"", http.header_name[cnth], http.header_value[cnth]);
                    }
                    if(strlen(http.body)) {
                        len = strlen(msg);
                        if(msg_size - len - 1 > (int)strlen(http.body) + 32)
                            snprintf(msg + len , msg_size - len, ", \"_Body\": \"%s\"", http.body);
                    }
                    len = strlen(msg);
                    snprintf(msg + len, msg_size - len, "}");
                } else if (app_msg->type == APP_HTTP) {
                    if(idx > 1)
                        msg = mkjson(MKJ_OBJ, 1, J_STRING, "_Exception", "HTTP Message Fragmentation");
                    else
                        msg = mkjson(MKJ_OBJ, 1, J_STRING, "_Exception", "ERROR");
                }

                if(cntm < mc) {
                    if(app_tx_msg_cnt < APP_MSG_MAX)
                        app_tx_msg[app_tx_msg_cnt++] = msg;
                    else
                        break;
                }
                else {
                    if(app_rx_msg_cnt < APP_MSG_MAX)
                        app_rx_msg[app_rx_msg_cnt++] = msg;
                    else
                        break;
                }
            }

            /* tx and rx message list */
            char app_rx_msg_list[APP_MSG_LEN_MAX] = {0};
            char app_tx_msg_list[APP_MSG_LEN_MAX] = {0};

            snprintf(app_tx_msg_list, sizeof(app_tx_msg_list), "[");
            for (cntm = 0; cntm < app_tx_msg_cnt ; cntm++) {
                len = strlen(app_tx_msg_list);
                snprintf(app_tx_msg_list + len, sizeof(app_tx_msg_list) - len, "%s, ",
                         app_tx_msg[cntm] && (strlen(app_tx_msg[cntm]) < sizeof(app_tx_msg_list) - len) ? app_tx_msg[cntm] : "{}");
            }
            len = strlen(app_tx_msg_list);
            if(app_tx_msg_cnt && len > 2)
                snprintf(app_tx_msg_list + (len - 2), sizeof(app_tx_msg_list) - (len - 2), "]");
            else
                snprintf(app_tx_msg_list, sizeof(app_tx_msg_list), "[]");
            for(cntm = 0; cntm < app_tx_msg_cnt; cntm++)
                free(app_tx_msg[cntm]);

            snprintf(app_rx_msg_list, sizeof(app_rx_msg_list), "[");
            for (cntm = 0; cntm < app_rx_msg_cnt ; cntm++) {
                len = strlen(app_rx_msg_list);
                snprintf(app_rx_msg_list + len, sizeof(app_rx_msg_list) - len, "%s, ",
                         app_rx_msg[cntm] && (strlen(app_rx_msg[cntm]) < sizeof(app_rx_msg_list) - len) ? app_rx_msg[cntm] : "{}");
            }
            len = strlen(app_rx_msg_list);
            if(app_rx_msg_cnt && len > 2)
                snprintf(app_rx_msg_list + (len - 2), sizeof(app_rx_msg_list) - (len - 2), "]");
            else
                snprintf(app_rx_msg_list, sizeof(app_rx_msg_list), "[]");
            for(cntm = 0; cntm < app_rx_msg_cnt; cntm++)
                free(app_rx_msg[cntm]);

            /* app, app tx and app rx */
            if(app_msg->type == APP_DNS) {
                json_obj[J_APP] = mkjson(MKJ_OBJ, 1, J_STRING, JKEY(I_APP), "DNS");
                if(app_tx_msg_cnt)
                    json_obj[J_APP_TX_DNS] = mkjson(MKJ_OBJ, 1, J_JSON, JKEY(I_APP_TX_DNS), app_tx_msg_list);
                if(app_rx_msg_cnt)
                    json_obj[J_APP_RX_DNS] = mkjson(MKJ_OBJ, 1, J_JSON, JKEY(I_APP_RX_DNS), app_rx_msg_list);
            }
            else {
                json_obj[J_APP] = mkjson(MKJ_OBJ, 1, J_STRING, JKEY(I_APP), "HTTP");
                if(app_tx_msg_cnt)
                    json_obj[J_APP_TX_HTTP] = mkjson(MKJ_OBJ, 1, J_JSON, JKEY(I_APP_TX_HTTP), app_tx_msg_list);
                if(app_rx_msg_cnt)
                    json_obj[J_APP_RX_HTTP] = mkjson(MKJ_OBJ, 1, J_JSON, JKEY(I_APP_RX_HTTP), app_rx_msg_list);
            }
        }
        else if (app_msg->cnt) {
            if(app_msg->type == APP_DNS)
                json_obj[J_APP] = mkjson(MKJ_OBJ, 1, J_STRING, JKEY(I_APP), "DNS");
            else
                json_obj[J_APP] = mkjson(MKJ_OBJ, 1, J_STRING, JKEY(I_APP), "HTTP");
        }

        /* merge json objects */
        for(cntj=0; cntj<JSON_OBJ_MAX; cntj++) {
            if(json_obj[cntj]) {
                if(cntj) {
                    len = strlen(json_msg) - 1;
                    snprintf(json_msg + len, sizeof(json_msg) - len, ", %s", strlen(json_obj[cntj] + 1) < sizeof(json_msg) - len ?
                             json_obj[cntj] + 1 : "{}");
                }
                else
                    snprintf(json_msg, sizeof(json_msg), "%s", strlen(json_obj[cntj]) < sizeof(json_msg) ?
                             json_obj[cntj] : "{}");
                free(json_obj[cntj]);
            }
        }
        if(config.output_type == JSON_FULL) {
            mkjson_prettify(json_msg, json_msg_full);
            json_out = json_msg_full;
        }
        else
            json_out = json_msg;

        /* send message via udp  */
        if (config.output_udp) {
            udp_send_msg(json_out, &config);
            if (config.output_udp_quiet)
                return 0;
        }

        /* print to stdout with ascii record separator when not daemon */
        if (!config.mode_daemon) {
            fprintf(stdout, "%s", json_out);
            fprintf(stdout, "\n%c\n", 0x1e);
            fflush(stdout);
        }

        return 0;
    }
    // clang-format on

    if (!((config.monitor & MONITOR_FILE) && r->type == RECORD_TYPE_FILE))
        return 0;

    /* get file path and name */
    rf = (struct RECORD_FS *)r;
    pfilepath = (char *)rf->filepath;
    pfilename = (char *)rf->filename;

    /* get file access, modification and change times */
    time_sec = rf->atime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec);
    strftime(ts, sizeof(ts), "%a, %b %d %Y %H:%M:%S", tm);
    snprintf(tsa, sizeof(tsa), "%s.%09lu UTC", ts, (rf->atime_nsec % (uint64_t)1e9));

    time_sec = rf->mtime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec);
    strftime(ts, sizeof(ts), "%a, %b %d %Y %H:%M:%S", tm);
    snprintf(tsm, sizeof(tsm), "%s.%09lu UTC", ts, (rf->mtime_nsec % (uint64_t)1e9));

    time_sec = rf->ctime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec);
    strftime(ts, sizeof(ts), "%a, %b %d %Y %H:%M:%S", tm);
    snprintf(tsc, sizeof(tsc), "%s.%09lu UTC", ts, (rf->ctime_nsec % (uint64_t)1e9));

    /* set cache update flags if modified */
    if (rf->event[I_CLOSE_WRITE]) {
        if (!strcmp(rf->filepath, "/etc/")) {
            if (!strcmp(rf->filename, "passwd"))
                cache_user_update = true;
            else if (!strcmp(rf->filename, "group"))
                cache_group_update = true;
            else if (!strcmp(rf->filename, "mtab"))
                cache_device_mount_update = true;
        }
        if (config.xfile_version) {
            if (!strcmp(rf->filepath, "/var/lib/rpm/")) {
                if (!strcmp(rf->filename, "rpmdb.sqlite"))
                    cache_version_update = true;
            } else if (!strcmp(rf->filepath, "/var/log/")) {
                if (!strcmp(rf->filename, "dpkg.log"))
                    cache_version_update = true;
            }
        }
    }

    /* print table output */
    if (config.output_type == TABLE_OUTPUT) {
        char evtlist[FS_EVENT_MAX * 3] = {0};
        strncpy(evtlist, S_ISLNK(rf->imode) ? "S" : (rf->inlink > 1 ? "H" : "F"), 1);
        for (cntf = 0; cntf < FS_EVENT_MAX; ++cntf)
            if (rf->event[cntf]) {
                strncat(evtlist, ",", sizeof(evtlist) - strlen(evtlist) - 1);
                strncat(evtlist, fsevt[cntf].shortname2, sizeof(evtlist) - strlen(evtlist) - 1);
                if (I_MOVED_TO == cntf && rf->filename_from[0]) {
                    strncpy(filename, rf->filename_from, sizeof(filename) - strlen(filename) - 1);
                    strncat(filename, ">", sizeof(filename) - strlen(filename) - 1);
                    strncat(filename, rf->filename_to, sizeof(filename) - strlen(filename) - 1);
                    pfilename = filename;
                }
            }
        fprintf(stdout, "%-12.12s  %-*.*s  %-5u  %-8s  %-*.*s  %-7u  %-7u  %-10u  %-*.*s  %-10lu  %-*.*s  %lu", &tsl[7],
                16, 16, evtlist, rf->events, dur, 15, 15, r->comm, r->ppid, r->pid, rf->ino, 20, 20, pfilename,
                rf->isize, 19, 19, tsa, record_count);
        fprintf(stdout, "\n");
        return 0;
    }

    /* check for rename event */
    for (cntf = 0; cntf < FS_EVENT_MAX; ++cntf)
        if (rf->event[cntf] && I_MOVED_TO == cntf)
            is_moved_to = true;

    /* get file permissions */
    strncpy(mode, "----------", sizeof(mode) - 1);
    if (S_ISLNK(rf->imode))
        mode[0] = 'l';
    for (cntp = 0; cntp <= I_OTHER_EXE; cntp++)
        if (rf->imode & fsperm[cntp].value) {
            mode[cntp + 1] = fsperm[cntp].perm;
            if (config.file_checksum || config.xfile_version) {
                if (cntp == I_USER_EXE || cntp == I_GROUP_EXE || cntp == I_OTHER_EXE)
                    is_hashed = true;
            }
        }

    /* cache md5 and sha256 */
    if (is_hashed) {
        bool found = !bpf_map__lookup_elem(map_xf, rf->filename, TASK_COMM_LEN, &xf_file, sizeof(struct XFILES), 0);
        if (config.file_checksum && rf->filepath[0] && rf->filename[0]) {
            if (!xf_file.md5 || !xf_file.sha256 || rf->isize != xf_file.size ||
                (rf->mtime_nsec / (uint64_t)1e9 != xf_file.mtime)) {
                if (found) {
                    if (xf_file.md5)
                        free(xf_file.md5);
                    if (xf_file.sha256)
                        free(xf_file.sha256);
                }
                if (strcspn(rf->filename, ign) == strlen(rf->filename)) {
                    if (plugin_virus_get_checksum) {
                        plugin_virus_get_checksum(CHECKSUM_TYPE_MD5, rf->filepath, rf->filename, md5);
                        plugin_virus_get_checksum(CHECKSUM_TYPE_SHA256, rf->filepath, rf->filename, sha256);
                    }
                    xf_file.md5 = strdup(md5);
                    xf_file.sha256 = strdup(sha256);
                }
                xf_file.size = rf->isize;
                xf_file.mtime = rf->mtime_nsec / (uint64_t)1e9;
                bpf_map__update_elem(map_xf, rf->filename, TASK_COMM_LEN, &xf_file, sizeof(struct XFILES), BPF_ANY);
            }
        }
    }

    /* adjust file path based on mount point */
    if (cache_mount[rf->idev] && strlen(cache_mount[rf->idev]) > 1) {
        snprintf(filepath, sizeof(filepath), "%s%s", cache_mount[rf->idev], rf->filepath);
        pfilepath = filepath;
    }

    // clang-format off
    /* build json objects with mkjson */
    /* file */
    char file_perms[FILE_PERMS_LEN_MAX] = {0};
    char file_events[FILE_EVENTS_LEN_MAX] = {0};
    snprintf(file_perms, sizeof(file_perms), "%04o/%s", rf->imode & 0xFFF, mode);
    snprintf(file_events, sizeof(file_events), "{");
    for (cntf = 0; cntf < FS_EVENT_MAX; ++cntf) {
        if (rf->event[cntf]) {
            len = strlen(file_events);
            snprintf(file_events + len, sizeof(file_events) - len, "\"%s\": %u, ", fsevt[cntf].name, rf->event[cntf]);
            events += rf->event[cntf];
        }
    }
    len = strlen(file_events);
    if(events)
        snprintf(file_events + (len - 2), sizeof(file_events) - (len - 2), "}");
    else
        snprintf(file_events + len, sizeof(file_events) - len, "}");

    /* file */
    snprintf(ts1, sizeof(ts1), "%.09f", (r->ts - r->ts_first) / 1e9);
    snprintf(ts2, sizeof(ts2), "%.09f", (rf->mtime_nsec - rf->mtime_nsec_first) / 1e9);
    json_obj[J_FILE] = mkjson(MKJ_OBJ, 22,
        J_STRING, JKEY(I_FILE_PATH), pfilepath,
        J_STRING, JKEY(I_FILE), is_moved_to ? rf->filename_to : rf->filename,
        is_moved_to ?  J_STRING : J_IGN_STRING,
            JKEY(I_FILE_ORIGIN), rf->filename_from,
        config.xfile_version && is_hashed ? J_STRING : J_IGN_STRING,
            JKEY(I_FILE_VERSION), xf_file.version ? xf_file.version : "",
        J_STRING, JKEY(I_FILE_MODE), S_ISLNK(rf->imode) ? "symlink" : (rf->inlink > 1 ? "hardlink" : "regular"),
        J_UINT, JKEY(I_FILE_EVENT_COUNT), rf->events,
        J_JSON, JKEY(I_FILE_EVENTS), file_events,
        J_TIMESTAMP, JKEY(I_FILE_EVENTS_DURATION), r->ts - r->ts_first ? ts1 : "0",
        J_UINT, JKEY(I_FILE_INODE), rf->ino ? rf->ino : 0,
        J_UINT, JKEY(I_FILE_INODE_LINK_COUNT), rf->ino ? rf->inlink : 0,
        J_STRING, JKEY(I_FILE_DEVICE), rf->ino && cache_device[rf->idev] ? cache_device[rf->idev] : "",
        J_STRING, JKEY(I_FILE_PERMISSIONS), rf->ino ? file_perms: "",
        J_STRING, JKEY(I_FILE_USER),  rf->ino && cache_user[rf->iuid] ? cache_user[rf->iuid] : "",
        J_STRING, JKEY(I_FILE_GROUP),  rf->ino && cache_group[rf->igid] ? cache_group[rf->igid] : "",
        J_UINT, JKEY(I_FILE_UID), rf->ino ? rf->iuid : 0,
        J_UINT, JKEY(I_FILE_GID), rf->ino ? rf->igid : 0,
        J_LLUINT, JKEY(I_FILE_SIZE), rf->ino ? rf->isize : 0,
        rf->ino && rf->isize != rf->isize_first ? J_LLINT : J_IGN_LLINT,
            JKEY(I_FILE_SIZE_CHANGE), rf->isize - rf->isize_first,
        J_STRING, JKEY(I_FILE_ACCESS_TIME), rf->ino ? tsa : "",
        J_STRING, JKEY(I_FILE_STATUS_CHANGE_TIME), rf->ino ? tsc : "",
        J_STRING, JKEY(I_FILE_MODIFICATION_TIME), rf->ino ? tsm : "",
        rf->ino && rf->mtime_nsec != rf->mtime_nsec_first ? J_TIMESTAMP : J_IGN_TIMESTAMP,
            JKEY(I_FILE_MODIFICATION_TIME_CHANGE), rf->mtime_nsec - rf->mtime_nsec_first ? ts2 : "0");

    /* file checksums */
    if(config.file_checksum && is_hashed) {
        json_obj[J_FILE_CHECKSUM] = mkjson(MKJ_OBJ, 2,
           J_STRING, JKEY(I_FILE_CHECKSUM_MD5), xf_file.md5 ? xf_file.md5 : "",
           J_STRING, JKEY(I_FILE_CHECKSUM_SHA256), xf_file.sha256 ? xf_file.sha256 : "");
    }
    //clang-format on

    /* merge json objects */
    for (cntj = 0; cntj < JSON_OBJ_MAX; cntj++) {
        if (json_obj[cntj]) {
            if (cntj) {
                len = strlen(json_msg) - 1;
                snprintf(json_msg + len, sizeof(json_msg) - len, ", %s", json_obj[cntj] + 1);
            } else
                snprintf(json_msg, sizeof(json_msg), "%s", json_obj[cntj]);
            free(json_obj[cntj]);
        }
    }
    if(config.output_type == JSON_FULL) {
        mkjson_prettify(json_msg, json_msg_full);
        json_out = json_msg_full;
    }
    else
        json_out = json_msg;

    /* send message via udp  */
    if (config.output_udp) {
        udp_send_msg(json_out, &config);
        if (config.output_udp_quiet)
            return 0;
    }

    /* print to stdout with ascii record separator when not daemon */
    if (!config.mode_daemon) {
        fprintf(stdout, "%s", json_out);
        fprintf(stdout, "\n%c\n", 0x1e);
        fflush(stdout);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    int                 check[CHECK_MAX] = {c_ok, c_ok, c_ok};
    char                checkmsg[CHECK_MSG_LEN_MAX];
    int                 sock;
    struct sockaddr_in  name;
    socklen_t           namelen = sizeof(name);
    struct timespec     spec;
    struct addrinfo     hints = {0};
    struct addrinfo    *res = NULL;
    struct XFILES       xf_proc = {0};
    char               *curr_key_xfile;
    char                next_key_xfile[TASK_COMM_LEN] = {0};
    char                cmd_output[CMD_OUTPUT_LEN_MAX] = {0};
    char                cmd[CMD_LEN_MAX] = {0};
    int                 kversion = 0;
    int                 kmajor = 0;
    int                 kminor = 0;
    struct stat         stats = {0};
    FILE               *fp = NULL;
    char               *token;
    bool                invalid = false;
    int                 jit_enable = 0;
    int                 err;
    int                 opt;
    long                pos;
    char               *pport;
    int                 argn = 1;
    int                 exes = 0;
    bool                dns_port_set = false;
    bool                http_port_set = false;
    short               port_num;
    int                 cnta;
    int                 cntp;
    int                 cnt;

    /* initialize default config */
    config.output_type = JSON_FULL;
    config.agg_idle_timeout = SOCK_IDLE_TIMEOUT;
    config.agg_active_timeout = SOCK_ACTIVE_TIMEOUT;
    config.app_proto[APP_DNS][0] = IPPROTO_UDP;
    config.app_proto[APP_DNS][1] = IPPROTO_TCP;
    config.app_port[APP_DNS][0] = config.app_port[APP_DNS][1] = DNS_PORT;
    config.app_port_num[APP_DNS] = 2;
    config.app_proto[APP_HTTP][0] = IPPROTO_TCP;
    config.app_port[APP_HTTP][0] = HTTP_PORT;
    config.app_port_num[APP_HTTP] = 1;

    /* get system info and parse command line options */
    uname(&utsn);
    while ((opt = getopt_long(argc, argv, ":m:e:t:o:vcp:u:qdT:lhVD:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            token = strtok(optarg, ",");
            do {
                if (token && !strncmp(token, "file", strlen(token)))
                    config.monitor |= MONITOR_FILE;
                else if (token && !strncmp(token, "socket", strlen(token)))
                    config.monitor |= MONITOR_SOCK;
                else
                    usage("Invalid kernel subsystem for -m option specified");
            } while ((token = strtok(NULL, ",")) != NULL);
            argn += 2;
            break;
        case 'e':
            config.agg_events_max = atoi(optarg);
            for (cnt = 0; cnt < (int)strlen(optarg); cnt++)
                if (!isdigit(optarg[cnt]))
                    invalid = true;
            if (invalid || config.agg_events_max <= 0) {
                usage("Invalid max number of file system events specified");
            }
            argn += 2;
            break;
        case 't':
            token = strtok(optarg, ",");
            do {
                if (token) {
                    for (cnt = 0; cnt < (int)strlen(token); cnt++)
                        if (!isdigit(token[cnt]))
                            invalid = true;
                    if (token == optarg)
                        config.agg_idle_timeout = atoi(token);
                    else
                        config.agg_active_timeout = atoi(token);
                } else
                    invalid = true;
            } while (!invalid && (token = strtok(NULL, ",")) != NULL);
            if (invalid || !config.agg_idle_timeout || !config.agg_active_timeout) {
                usage("Invalid network socket timeout specified");
            }
            argn += 2;
            break;
        case 'o':
            if (strlen(optarg) > 5) {
                if (!strncmp(optarg, "json-min", strlen(optarg)))
                    config.output_type = JSON_MIN;
                else
                    invalid = true;
            } else {
                if (!strncmp(optarg, "json", strlen(optarg)))
                    config.output_type = JSON_FULL;
                else if (!strncmp(optarg, "table", strlen(optarg)))
                    config.output_type = TABLE_OUTPUT;
                else
                    invalid = true;
            }
            if (invalid)
                usage("Invalid output option specified");
            argn += 2;
            break;
        case 'v':
            config.xfile_version = true;
            argn++;
            break;
        case 'c':
            config.file_checksum = true;
            argn++;
            break;
        case 'p':
            if (!strncmp(optarg, "dns=off", 8))
                config.app_port_num[APP_DNS] = 0;
            else if (!strncmp(optarg, "http=off", 8))
                config.app_port_num[APP_HTTP] = 0;
            else {
                token = strtok(optarg, "=");
                TOLOWER_STR(token);
                if (!strncmp(token, "dns", 4)) {
                    if (dns_port_set)
                        usage("DNS port(s) specified repeatedly");
                    dns_port_set = true;
                    config.app_port_num[APP_DNS] = 0;
                    while ((token = strtok(NULL, ",")) != NULL) {
                        port_num = config.app_port_num[APP_DNS];
                        TOLOWER_STR(token);
                        if ((int)strlen(token) < 5 || (strncmp(token, "tcp/", 4) && strncmp(token, "udp/", 4)))
                            usage("Invalid transport protocol for DNS port(s) specified");
                        for (cnt = 4; cnt < (int)strlen(token); cnt++)
                            if (!isdigit(token[cnt]))
                                invalid = true;
                        if (invalid || strlen(token) > 9)
                            usage("Invalid DNS port(s) specified");
                        config.app_proto[APP_DNS][port_num] = (!strncmp(token, "tcp/", 4) ? IPPROTO_TCP : IPPROTO_UDP);
                        config.app_port[APP_DNS][port_num] = atoi(&token[4]);
                        for (cnt = 0; cnt < port_num; cnt++)
                            if (config.app_proto[APP_DNS][cnt] == config.app_proto[APP_DNS][port_num] &&
                                config.app_port[APP_DNS][cnt] == config.app_port[APP_DNS][port_num])
                                usage("Duplicate DNS ports specified");
                        if (++config.app_port_num[APP_DNS] > APP_PORT_MAX)
                            usage("Too many DNS ports specified");
                    }
                    if (!config.app_port_num[APP_DNS])
                        usage("No DNS port specified");
                } else if (!strncmp(token, "http", 5)) {
                    // TBD: consolidate
                    if (http_port_set)
                        usage("HTTP port(s) specified repeatedly");
                    http_port_set = true;
                    config.app_port_num[APP_HTTP] = 0;
                    while ((token = strtok(NULL, ",")) != NULL) {
                        port_num = config.app_port_num[APP_HTTP];
                        TOLOWER_STR(token);
                        if ((int)strlen(token) < 5 || strncmp(token, "tcp/", 4))
                            usage("Invalid transport protocol for HTTP port(s) specified");
                        for (cnt = 4; cnt < (int)strlen(token); cnt++)
                            if (!isdigit(token[cnt]))
                                invalid = true;
                        if (invalid || strlen(token) > 9)
                            usage("Invalid HTTP port(s) specified");
                        config.app_proto[APP_HTTP][port_num] = IPPROTO_TCP;
                        config.app_port[APP_HTTP][port_num] = atoi(&token[4]);
                        for (cnt = 0; cnt < port_num; cnt++)
                            if (config.app_proto[APP_HTTP][cnt] == config.app_proto[APP_HTTP][port_num] &&
                                config.app_port[APP_HTTP][cnt] == config.app_port[APP_HTTP][port_num])
                                usage("Duplicate HTTP ports specified");
                        if (++config.app_port_num[APP_HTTP] > APP_PORT_MAX)
                            usage("Too many HTTP ports specified");
                    }
                    if (!config.app_port_num[APP_HTTP])
                        usage("No HTTP port specified");
                } else
                    usage("Invalid format for DNS or HTTP port(s) specified");
            }
            argn += 2;
            break;
        case 'u':
            token = strtok(optarg, ",");
            do {
                char buf[IP_ADDR_LEN_MAX];
                pos = strrchr(token, ':') - token;
                if (pos <= 0)
                    usage("Invalid udp host or port specified");
                pport = token + pos + 1;
                token[pos] = 0;
                for (cnt = 0; cnt < (int)strlen(pport); cnt++)
                    if (!isdigit(pport[cnt]))
                        invalid = true;
                if (invalid || !atoi(pport) || strlen(pport) > 5)
                    usage("Invalid udp port specified");
                if (inet_pton(AF_INET, token, buf) > 0)
                    config.output_udp_family[config.output_udp_num] = AF_INET;
                else if (inet_pton(AF_INET6, token, buf) > 0)
                    config.output_udp_family[config.output_udp_num] = AF_INET6;
                else
                    usage("Invalid udp ipv4 or ipv6 address specified");
                strncpy(config.output_udp_host[config.output_udp_num], token, INET6_ADDRSTRLEN - 1);
                config.output_udp_port[config.output_udp_num] = atoi(pport);
                config.output_udp = true;
                if (++config.output_udp_num >= UDP_SERVER_MAX)
                    usage("Too many udp hosts specified");
            } while ((token = strtok(NULL, ",")) != NULL);
            argn += 2;
            break;
        case 'q':
            config.output_udp_quiet = true;
            argn++;
            break;
        case 'd':
            config.mode_daemon = true;
            argn++;
            break;
        case 'T':
            if (strlen(optarg) > sizeof(config.token) - 1)
                usage("Invalid token with too many characters specified");
            strncpy(config.token, optarg, sizeof(config.token) - 1);
            argn += 2;
            break;
        case 'l':
            legend();
            break;
        case 'h':
            usage("");
            break;
        case 'V':
            config.verbose = true;
            argn++;
            break;
        case 'D':
            if (strlen(optarg) > sizeof(config.debug) - 1)
                usage("Invalid debug filter with too many characters specified");
            strncpy(config.debug, optarg, sizeof(config.debug) - 1);
            argn += 2;
            break;
        case 0:
            if (opt_version) {
                char dt[DATETIME_LEN_MAX];
                strncpy(dt, DATETIME, DATETIME_LEN_MAX);
                dt[11] = 0x20;
                fprintf(stdout, "kflowd " VERSION " (built %s, Linux %s, %s, clang %s, glibc %u.%u, libbpf %s)\n", dt,
                        utsn.release, ARCH, CLANG_VERSION, __GLIBC__, __GLIBC_MINOR__, LIBBPF_VERSION);
            }
            return 0;
        case '?':
            usage("Invalid argument specified");
            break;
        }
    }

    /* validate options */
    if (!config.monitor)
        config.monitor = MONITOR_FILE | MONITOR_SOCK;
    if ((config.mode_daemon || config.output_udp_quiet) && !config.output_udp)
        usage("Invalid option -d or -q without -u specified");
    if (config.output_type == TABLE_OUTPUT && config.output_udp)
        usage("Invalid option -u for table output specified.");
    if (argc != argn)
        usage("Invalid number of arguments specified");

    /* check effective uid and get pid */
    if (geteuid()) {
        fprintf(stderr, "Run this program with sudo or as root user\n");
        return 1;
    }

    /* init libbpf errors and debug info callback */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* add signal handlers  */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* open ebpf program and set options */
    skel = kflowd_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* start in daemon or terminal mode */
    if (config.mode_daemon) {
        if (daemon(true, true)) {
            fprintf(stderr, "\nFailed to start kflowd in daemon mode\n");
            return 1;
        }
    }

    /* try to load plugins */
    chdir(dirname(argv[0]));
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_DNS, RTLD_LAZY);
    if (!plugin_handle || !(plugin_dns_decode = dlsym(plugin_handle, "plugin_dns_decode")))
        plugin_dns_decode = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_HTTP, RTLD_LAZY);
    if (!plugin_handle || !(plugin_http_decode = dlsym(plugin_handle, "plugin_http_decode")))
        plugin_http_decode = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_VIRUS, RTLD_LAZY);
    if (!plugin_handle || !(plugin_virus_get_checksum = dlsym(plugin_handle, "plugin_virus_get_checksum")))
        plugin_virus_get_checksum = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_VULN, RTLD_LAZY);
    if (!plugin_handle || !(plugin_vuln_version_cache = dlsym(plugin_handle, "plugin_vuln_version_cache")))
        plugin_vuln_version_cache = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_DEVICE, RTLD_LAZY);
    if (!plugin_handle || !(plugin_device_cache = dlsym(plugin_handle, "plugin_device_cache")))
        plugin_device_cache = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_INTERFACE, RTLD_LAZY);
    if (!plugin_handle || !(plugin_interface_cache = dlsym(plugin_handle, "plugin_interface_cache")))
        plugin_interface_cache = NULL;
    plugin_handle = dlopen(PLUGIN_PATH PLUGIN_MOD_USER_GROUP, RTLD_LAZY);
    if (!plugin_handle || !(plugin_user_group_cache = dlsym(plugin_handle, "plugin_user_group_cache")))
        plugin_user_group_cache = NULL;

    /* set globals shared between user and kernel */
    clock_gettime(CLOCK_MONOTONIC, &spec);
    skel->rodata->ts_start = (uint64_t)((spec.tv_sec * (uint64_t)1e9) + spec.tv_nsec);
    skel->rodata->agg_events_max = config.agg_events_max;
    skel->rodata->agg_idle_timeout = config.agg_idle_timeout;
    skel->rodata->agg_active_timeout = config.agg_active_timeout;
    for (cnt = 0; cnt < config.output_udp_num; cnt++)
        skel->rodata->output_udp_port[cnt] = config.output_udp_port[cnt];
    for (cnta = 0; cnta < APP_MAX; cnta++)
        for (cntp = 0; cntp < config.app_port_num[cnta]; cntp++) {
            skel->rodata->app_proto[cnta][cntp] = config.app_proto[cnta][cntp];
            skel->rodata->app_port[cnta][cntp] = config.app_port[cnta][cntp];
        }
    memcpy(skel->rodata->debug, config.debug, DBG_LEN_MAX);
    skel->rodata->pid_self = getpid();

    /* get pid and pid of shell: kflowd -> sudo -> bash */
    sprintf(cmd, "$(command -v cat) /proc/%u/stat | cut -d\" \" -f4", getppid());
    if ((fp = popen(cmd, "r")) && fgets(cmd_output, sizeof(cmd_output), fp)) {
        skel->rodata->pid_shell = atoi(cmd_output);
        pclose(fp);
    }

    /* Load ebpf programs */
    err = kflowd_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* attach kprobes to kernel functions */
    err = kflowd_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* attach raw socket to bpf socket filter program */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "Failed to open raw socket\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(skel->progs.handle_skb);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        fprintf(stderr, "Failed to attach to raw socket\n");
        return 1;
    }

    /* init ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_records), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* print header and title */
    fprintf(stderr, "%s", title_str);

    /* check runtime requirements */
    fprintf(stderr, "\nRuntime Requirements:\n");
    sscanf(utsn.release, "%u.%u.%u", &kversion, &kmajor, &kminor);

    /* check kernel version */
    if (kversion < KERNEL_VERSION_MIN || (kversion == KERNEL_VERSION_MIN && kmajor < KERNEL_MAJOR_MIN))
        check[0] = c_fail;
    sprintf(checkmsg, "\e[0;%s\e[0m Kernel version %u.%u+ required", check[0] ? "32m[ok]" : "31m[fail]",
            KERNEL_VERSION_MIN, KERNEL_MAJOR_MIN);
    fprintf(stderr, "%s -> Kernel %u.%u.%u installed\n", checkmsg, kversion, kmajor, kminor);
    int msglen = strlen(checkmsg);

    /* check vmlinux */
    check[1] = c_fail;
    if (!stat(SYS_FILE_VMLINUX, &stats))
        if (stats.st_size > 1)
            check[1] = c_ok;
    sprintf(checkmsg, "\e[0;%s\e[0m vmlinux (BTF & CO-RE)", check[1] ? "32m[ok]" : "31m[fail]");
    fprintf(stderr, "%s%*s -> %s at /sys/kernel/btf/vmlinux\n", checkmsg, msglen - (int)strlen(checkmsg), "",
            check[1] ? "Available" : "Not available");

    /* check jit compiler */
    check[2] = c_fail;
    jit_enable = -1;
    fp = fopen(SYS_FILE_JIT_ENABLE, "r");
    if (fp) {
        if (fscanf(fp, "%u", &jit_enable) != -1) {
            if (jit_enable == 1)
                check[2] = c_ok;
            else if (jit_enable == 2)
                check[2] = c_warn;
            fclose(fp);
        }
    }
    sprintf(checkmsg, "\e[0;%s\e[0m JIT Compiler",
            check[2] == c_warn ? "33m[warn]" : (check[2] ? "32m[ok]" : "31m[fail]"));
    fprintf(stderr, "%s%*s -> %s (net.core.bpf_jit_enable=%d)\n", checkmsg, msglen - (int)strlen(checkmsg), "",
            check[2] == c_warn ? "Enabled with debug" : (check[2] ? "Enabled" : "Disabled"), jit_enable);
    fprintf(stderr, "\n");

    /* exit on at least one fail */
    if (!check[0] || !check[1] || !check[2]) {
        fprintf(stderr, "\nkflowd failed to start!\n\n");
        exit(EXIT_FAILURE);
    }

    /* get host ip */
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (!getaddrinfo("8.8.8.8", "53", &hints, &res) &&
        (sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) >= 0) {
        connect(sock, (const struct sockaddr *)res->ai_addr, res->ai_addrlen);
        getsockname(sock, (struct sockaddr *)&name, &namelen);
        inet_ntop(res->ai_family, &name.sin_addr, hostip, INET6_ADDRSTRLEN);
        freeaddrinfo(res);
        close(sock);
    }
    if (!hostip[0])
        fprintf(stderr, "\nWarning: Failed to get host ip!\n\n");

    /* get map and build version cache */
    if (config.file_checksum || config.xfile_version) {
        map_xf = skel->maps.hash_xfiles;
        if (config.xfile_version)
            if(plugin_vuln_version_cache)
                plugin_vuln_version_cache(map_xf, &exes, argv[0], config.mode_daemon, VERSION);
    }

    /* print plugin status */
    fprintf(stderr, "Plugin Modules:\n");
    fprintf(stderr, "\e[0;%s\e[0m DNS:         %s DNS Decoder Module (kflowd_mod_dns.so)\n", plugin_dns_decode ? "32m[+]" : "33m[-]",
            plugin_dns_decode ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m HTTP:        %s HTTP Decoder Module (kflowd_mod_http.so)\n", plugin_http_decode ? "32m[+]" : "33m[-]",
            plugin_http_decode ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m Virus:       %s Virus Checksum Module (kflowd_mod_virus.so)\n", plugin_virus_get_checksum ? "32m[+]" : "33m[-]",
            plugin_virus_get_checksum ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m Vuln:        %s File/Process Version Vulnerability Module (kflowd_mod_vuln.so)\n", plugin_vuln_version_cache ? "32m[+]" : "33m[-]",
            plugin_vuln_version_cache ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m Device:      %s File Device Id Module (kflowd_mod_device.so)\n", plugin_device_cache ? "32m[+]" : "33m[-]",
            plugin_device_cache ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m Interface:   %s Network Interface Id Module (kflowd_mod_interface.so)\n", plugin_interface_cache ? "32m[+]" : "33m[-]",
            plugin_interface_cache ? "Loaded" : "NOT loaded");
    fprintf(stderr, "\e[0;%s\e[0m User-Group:  %s File/Process User-Group Id Module (kflowd_mod_user_group.so)\n", plugin_user_group_cache ? "32m[+]" : "33m[-]",
            plugin_user_group_cache ? "Loaded" : "NOT loaded");

    fprintf(stderr, "\n");

    /* print config options and success */
    fprintf(stderr, "Configuration:\n");
    fprintf(stderr, "\e[0;32m[+]\e[0m Monitored kernel subsystem(s)\n");
    fprintf(stderr, "\e[0;%s\e[0m   \e[%sFile System:     %7u max records at %lu bytes \e[0m\n", config.monitor & MONITOR_FILE ? "32m[+]" : "33m[-]",
            ((config.monitor & MONITOR_FILE) || config.mode_daemon) ? "0m" : "0:37m", MAP_RECORDS_MAX, sizeof(struct RECORD_FS));
    fprintf(stderr, "\e[0;%s\e[0m   \e[%sNetwork sockets: %7u max records at %lu bytes\e[0m\n", config.monitor & MONITOR_SOCK ? "32m[+]" : "33m[-]",
            ((config.monitor & MONITOR_SOCK) || config.mode_daemon) ? "0m" : "0:37m", MAP_SOCKS_MAX, sizeof(struct RECORD_SOCK));
    if (config.monitor & MONITOR_FILE) {
        fprintf(stderr, "\e[0;%s\e[0m Filesystem aggregation by PID+Inode until\n",
                config.agg_events_max == 1 ? "33m[-]" : "32m[+]");
        fprintf(stderr, "\e[0;%s\e[0m   Finished file operation\n", "32m[+]");
        if (config.agg_events_max)
            fprintf(stderr, "\e[0;32m[+]\e[0m   \e[%sMax number of %.0u%sevent%s\e[0m\n",
                    (config.agg_events_max || config.mode_daemon) ? "0m" : "0:37m", config.agg_events_max,
                    config.agg_events_max ? " " : "", config.agg_events_max == 1 ? " (no aggregation)" : "s");
    }
    if (config.monitor & MONITOR_SOCK) {
        fprintf(stderr, "\e[0;32m[+]\e[0m Network aggregation by Protocol+SrcIP+SrcPort+DstIP+DstPort until\n");
        fprintf(stderr, "\e[0;32m[+]\e[0m   Idle timeout:   %5u seconds\n", config.agg_idle_timeout);
        fprintf(stderr, "\e[0;32m[+]\e[0m   Active timeout: %5u seconds\n", config.agg_active_timeout);
    }
    if (config.app_port_num[APP_DNS] || config.app_port_num[APP_HTTP]) {
        fprintf(stderr, "\e[0;32m[+]\e[0m Application monitoring for up to %u messages per record\n", APP_MSG_MAX);
        if (config.app_port_num[APP_DNS]) {
            fprintf(stderr, "\e[0;32m[+]  \e[0m DNS:  ");
            for (cnt = 0; cnt < config.app_port_num[APP_DNS]; cnt++)
                fprintf(stderr, "%s%s%u", cnt ? ", " : " ",
                        config.app_proto[APP_DNS][cnt] == IPPROTO_TCP ? "tcp/" : "udp/", config.app_port[APP_DNS][cnt]);
            fprintf(stderr, "\n");
        }
        if (config.app_port_num[APP_HTTP]) {
            fprintf(stderr, "\e[0;32m[+]  \e[0m HTTP:  ");
            for (cnt = 0; cnt < config.app_port_num[APP_HTTP]; cnt++)
                fprintf(stderr, "%stcp/%u", cnt ? ", " : "", config.app_port[APP_HTTP][cnt]);
            fprintf(stderr, "\n");
        }
    }

    if (config.xfile_version)
        fprintf(stderr, "\e[0;%s\e[0m %sPackage-based version identification for %u executables enabled\n",
                exes ? "32m[+]" : "33m[+]", exes ? "" : "\e[0;33mWarning: \e[0m", exes);
    if (config.file_checksum)
        fprintf(stderr, "\e[0;32m[+]\e[0m MD5 and SHA256 calculation for executable and "
                        "library files enabled\n");
    fprintf(stderr, "\e[0;%s\e[0m Output as %s to stdout\n",
            (config.output_udp && (config.mode_daemon || config.output_udp_quiet)) ? "33m[-]" : "32m[+]",
            config.output_type == JSON_FULL    ? "json"
            : config.output_type == JSON_MIN   ? "json-min"
                                               : "table");
    if (config.output_udp)
        for (cnt = 0; cnt < config.output_udp_num; cnt++)
            fprintf(stderr, "\e[0;32m[+]\e[0m Output to UDP server %s%s%s:%u\n",
                    config.output_udp_family[cnt] == AF_INET6 ? "[" : "", config.output_udp_host[cnt],
                    config.output_udp_family[cnt] == AF_INET6 ? "]" : "", config.output_udp_port[cnt]);
    if (config.verbose)
        fprintf(stderr, "\e[0;32m[+]\e[0m Verbose mode for userspace app enabled\n");
    if (config.debug[0])
        fprintf(stderr, "\e[0;32m[+]\e[0m Debug mode for kernel ebpf program enabled. Run command\n"
                        "      'sudo cat /sys/kernel/debug/tracing/trace_pipe'\n");
    fprintf(stderr, "\nkflowd (" VERSION ") with PID %u successfully started in %s mode\n\n", skel->rodata->pid_self,
            config.mode_daemon ? "daemon" : "terminal");
    if (!(config.mode_daemon || config.output_udp_quiet)) {
        fprintf(stderr, "Press <RETURN> key for output\n");
        while (getchar() != '\n') {
        };
        fprintf(stderr, "\033[A\33[2K\033[A\33[2K\r");
    }

    /* start the clock */
    clock_gettime(CLOCK_REALTIME, &spec_start);
    skel->data->monitor = config.monitor;
    running = true;

    /* print header if table output */
    if (config.output_type == TABLE_OUTPUT)
        printf("%-12s  %-16s  %-4s  %-7s  %-15s  %-7s  %-7s  %-10s  %-20s  %-10s  %-19s  %s\n", "TIME", "EVENTS",
               "COUNT", "DURATION", "PROCESS", "PPID", "PID*", "INODE*", "FILENAME", "SIZE", "LAST ACCESS", "#");

    while (running) {
        /* update user and group cache on change */
        clock_gettime(CLOCK_REALTIME, &spec);
        if (cache_user_update && cache_user_mtime + 5 < spec.tv_sec) {
            cache_user_update = false;
            if(plugin_user_group_cache)
                plugin_user_group_cache(CACHE_TYPE_USER, cache_user);
            cache_user_mtime = spec.tv_sec;
        }
        if (cache_group_update && cache_group_mtime + 5 < spec.tv_sec) {
            cache_group_update = false;
            if(plugin_user_group_cache)
                plugin_user_group_cache(CACHE_TYPE_GROUP, cache_group);
            cache_group_mtime = spec.tv_sec;
        }
        if (cache_device_mount_update && cache_device_mount_mtime + 10 < spec.tv_sec) {
            cache_device_mount_update = false;
            if(plugin_device_cache)
                plugin_device_cache(cache_device, cache_mount);
            cache_device_mount_mtime = spec.tv_sec;
        }

        /* update xfile version cache on change */
        if (config.xfile_version) {
            if (cache_version_update && cache_version_mtime + 20 < spec.tv_sec) {
                cache_version_update = false;
                if(plugin_vuln_version_cache)
                    plugin_vuln_version_cache(map_xf, &exes, argv[0], config.mode_daemon, VERSION);
                cache_version_mtime = spec.tv_sec;
                fprintf(stderr, "Updated version cache\n");
            }
        }

        /* update interface cache */
        if (cache_interface_update) {
            cache_interface_update = false;
            if(plugin_interface_cache)
                plugin_interface_cache(cache_interface);
        }

        /* poll with timeout */
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ringbuffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* free ringbuffer */
    ring_buffer__free(rb);
    kflowd_bpf__destroy(skel);

    /* free various caches */
    for (cnt = 0; cnt < CACHE_ENTRIES_MAX; cnt++) {
        if (cache_user[cnt])
            free(cache_user[cnt]);
        if (cache_group[cnt])
            free(cache_group[cnt]);
        if (cache_device[cnt])
            free(cache_device[cnt]);
        if (cache_mount[cnt])
            free(cache_mount[cnt]);
    }

    /* free version cache of xfiles */
    if (config.xfile_version) {
        curr_key_xfile = NULL;
        while (!bpf_map__get_next_key(map_xf, curr_key_xfile, next_key_xfile, TASK_COMM_LEN)) {
            if (!bpf_map__lookup_elem(map_xf, next_key_xfile, TASK_COMM_LEN, &xf_proc, sizeof(struct XFILES), 0)) {

                if (xf_proc.package)
                    free(xf_proc.package);
                if (xf_proc.version)
                    free(xf_proc.version);
                if (xf_proc.md5)
                    free(xf_proc.md5);
                if (xf_proc.sha256)
                    free(xf_proc.sha256);
            }
            curr_key_xfile = next_key_xfile;
        }
    }

    return err < 0 ? -err : 0;
}

static int udp_send_msg(char *msg, struct CONFIG *config) {
    int                 sock;
    struct sockaddr_in6 server_addr;
    char                server6[INET6_ADDRSTRLEN + 8] = {0};
    char               *server;
    int                 cnt;

    /* create dual udp/udp6 socket */
    sock = socket(PF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Failed to create UDP socket");
        return 1;
    }

    for (cnt = 0; cnt < config->output_udp_num; cnt++) {
        /* convert server to ipv6 if ipv4 */
        server = config->output_udp_host[cnt];
        if (AF_INET == config->output_udp_family[cnt]) {
            snprintf(server6, sizeof(server6), "::FFFF:%s", config->output_udp_host[cnt]);
            server = server6;
        }

        /* send message */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, server, &server_addr.sin6_addr);
        server_addr.sin6_port = htons(config->output_udp_port[cnt]);
        if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Failed to send message to UDP server:");
            close(sock);
            return 1;
        }
    }

    /* close udp socket */
    close(sock);

    return 0;
}
/*
 * json encoder derived from mkjson library under MIT license
 * https://github.com/Jacajack/mkjson
 */
static int mkjson_sprintf(char **strp, const char *fmt, ...) {
    int     len;
    va_list ap;
    char   *buf;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    if (len >= 0) {
        buf = malloc(++len);
        if (buf != NULL) {
            va_end(ap);
            va_start(ap, fmt);

            /* write and return the data */
            len = vsnprintf(buf, len, fmt, ap);
            if (len >= 0) {
                *strp = buf;
            } else {
                free(buf);
            }
        }
    }
    va_end(ap);

    return len;
}

static char *mkjson_prettify(const char *s, char *r) {
    int  indent = 0;
    bool array = false;
    bool quoted = false;

    /* iterate over JSON string.*/
    for (const char *x = s; *x != '\0'; x++) {
        if (*x == '"')
            quoted = !quoted;
        if (quoted) {
            *r++ = *x;
            continue;
        }
        if (*x == '{') {
            indent += 2;
            array = false;
            *r++ = *x;
            *r++ = '\n';
            for (int i = 0; i < indent; i++)
                *r++ = ' ';
        } else if (*x == '[') {
            if (array == true) {
                *r++ = '\n';
                indent += 2;
                for (int i = 0; i < indent; i++)
                    *r++ = ' ';
            }
            array = true;
            *r++ = *x;
        } else if (*x == ']') {
            if (array == false && *(r - 1) != '}') {
                *r++ = '\n';
                indent -= 2;
                for (int i = 0; i < indent; i++)
                    *r++ = ' ';
            }
            array = false;
            *r++ = *x;
        } else if (*x == '}') {
            indent -= 2;
            array = false;
            *r++ = '\n';
            for (int i = 0; i < indent; i++)
                *r++ = ' ';
            *r++ = *x;
        } else if (*x == ',' && array == false) {
            *r++ = *x;
            *r++ = '\n';
            for (int i = 0; i < indent - 1; i++)
                *r++ = ' ';
        } else
            *r++ = *x;
    }
    *r = '\0';

    return r;
}

static char *mkjson(enum MKJSON_CONTAINER_TYPE otype, int count, ...) {
    int                    i, size, len, goodchunks = 0, failure = 0;
    char                  *json, *prefix, **chunks, ign;
    enum MKJSON_VALUE_TYPE vtype;
    const char            *key;
    long long int          intval;
    long double            dblval;
    const char            *strval;

    if (count < 0 || (otype != MKJ_OBJ && otype != MKJ_ARR))
        return NULL;

    /* allocate chunk pointer array */
    chunks = calloc(count, sizeof(char *));
    if (chunks == NULL)
        return NULL;

    /* this should rather be at the point of no return */
    va_list ap;
    va_start(ap, count);

    /* reate chunks */
    for (i = 0; i < count && !failure; i++) {
        /* get value type and key */
        vtype = va_arg(ap, enum MKJSON_VALUE_TYPE);
        if (otype == MKJ_OBJ) {
            key = va_arg(ap, char *);
            if (key == NULL) {
                failure = 1;
                break;
            }
        } else
            key = "";

        /* generate prefix */
        if (mkjson_sprintf(&prefix, "%s%s%s", otype == MKJ_OBJ ? "\"" : "", key,
                           otype == MKJ_OBJ ? "\": " : "") == -1) {
            failure = 1;
            break;
        }

        /* check value type */
        ign = 0;
        switch (vtype) {
        /* gnore string / JSON data */
        case J_IGN_STRING:
        case J_IGN_TIMESTAMP:
        case J_IGN_JSON:
            (void)va_arg(ap, const char *);
            ign = 1;
            break;

        /* ignore int / long long int */
        case J_IGN_INT:
        case J_IGN_LLINT:
            if (vtype == J_IGN_INT)
                (void)va_arg(ap, int);
            else
                (void)va_arg(ap, long long int);
            ign = 1;
            break;

        /* ignore unsigned int / unsigned long long int */
        case J_IGN_UINT:
        case J_IGN_LLUINT:
            if (vtype == J_IGN_UINT)
                (void)va_arg(ap, unsigned int);
            else
                (void)va_arg(ap, unsigned long long int);
            ign = 1;
            break;

        /* ignore double / long double */
        case J_IGN_DOUBLE:
        case J_IGN_LDOUBLE:
            if (vtype == J_IGN_DOUBLE)
                (void)va_arg(ap, double);
            else
                (void)va_arg(ap, long double);
            ign = 1;
            break;

        /* Ignore boolean */
        case J_IGN_BOOL:
            (void)va_arg(ap, int);
            ign = 1;
            break;

        /* Ignore null value */
        case J_IGN_NULL:
            ign = 1;
            break;

        /* null-terminated string */
        case J_STRING:
            strval = va_arg(ap, const char *);

            /* if the pointer points to NULL, the string will be replaced with JSON null value */
            if (strval == NULL) {
                if (mkjson_sprintf(chunks + i, "%snull", prefix) == -1)
                    chunks[i] = NULL;
            } else {
                if (mkjson_sprintf(chunks + i, "%s\"%s\"", prefix, strval) == -1)
                    chunks[i] = NULL;
            }
            break;

        /* null-terminated string without quotes */
        /* dirk: added for timestamps with nanosecond precision */
        case J_TIMESTAMP:
            strval = va_arg(ap, const char *);

            /* If the pointer points to NULL, the string will be replaced with JSON null value */
            if (strval == NULL) {
                if (mkjson_sprintf(chunks + i, "%snull", prefix) == -1)
                    chunks[i] = NULL;
            } else {
                if (mkjson_sprintf(chunks + i, "%s%s", prefix, strval) == -1)
                    chunks[i] = NULL;
            }
            break;

        /* embed JSON data */
        case J_JSON:
            strval = va_arg(ap, const char *);

            /* if the pointer points to NULL, the JSON data is replaced with null value */
            if (mkjson_sprintf(chunks + i, "%s%s", prefix, strval == NULL ? "null" : strval) == -1)
                chunks[i] = NULL;
            break;

        /* int / long long int */
        case J_INT:
        case J_LLINT:
            if (vtype == J_INT)
                intval = va_arg(ap, int);
            else
                intval = va_arg(ap, long long int);

            if (mkjson_sprintf(chunks + i, "%s%Ld", prefix, intval) == -1)
                chunks[i] = NULL;
            break;

        /* unsigned int / long long unsigned int */
        case J_UINT:
        case J_LLUINT:
            if (vtype == J_UINT)
                intval = va_arg(ap, unsigned int);
            else
                intval = va_arg(ap, unsigned long long int);

            if (mkjson_sprintf(chunks + i, "%s%Lu", prefix, intval) == -1)
                chunks[i] = NULL;
            break;

        /* double / long double */
        case J_DOUBLE:
        case J_LDOUBLE:
            if (vtype == J_DOUBLE)
                dblval = va_arg(ap, double);
            else
                dblval = va_arg(ap, long double);

            if (dblval) {
                if (mkjson_sprintf(chunks + i, "%s%Lf", prefix, dblval) == -1)
                    chunks[i] = NULL;
            } else {
                if (mkjson_sprintf(chunks + i, "%s%Ld", prefix, (int)dblval) == -1)
                    chunks[i] = NULL;
            }
            break;

        /* double / long double */
        case J_SCI_DOUBLE:
        case J_SCI_LDOUBLE:
            if (vtype == J_SCI_DOUBLE)
                dblval = va_arg(ap, double);
            else
                dblval = va_arg(ap, long double);

            if (mkjson_sprintf(chunks + i, "%s%Le", prefix, dblval) == -1)
                chunks[i] = NULL;
            break;

        /* boolean */
        case J_BOOL:
            intval = va_arg(ap, int);
            if (mkjson_sprintf(chunks + i, "%s%s", prefix, intval ? "true" : "false") == -1)
                chunks[i] = NULL;
            break;

        /* JSON null */
        case J_NULL:
            if (mkjson_sprintf(chunks + i, "%snull", prefix) == -1)
                chunks[i] = NULL;
            break;

        /* bad type specifier */
        default:
            chunks[i] = NULL;
            break;
        }

        /* free prefix memory */
        free(prefix);

        /* NULL chunk without ignore flag indicates failure */
        if (!ign && chunks[i] == NULL)
            failure = 1;

        /* NULL chunk now indicates ignore flag */
        if (ign)
            chunks[i] = NULL;
        else
            goodchunks++;
    }

    /* we won't use ap anymore */
    va_end(ap);

    /* if everything is fine, merge chunks and create full JSON table */
    if (!failure) {
        /* get total length (this is without NUL byte) */
        size = 0;
        for (i = 0; i < count; i++)
            if (chunks[i])
                size += strlen(chunks[i]);

        /* total length = Chunks length + 2 brackets + separators */
        if (goodchunks == 0)
            goodchunks = 1;
        size = size + 2 + (goodchunks - 1) * 2;

        /* allocate memory for the whole thing */
        json = calloc(size + 1, sizeof(char));
        if (json) {
            /* merge chunks */
            json[0] = otype == MKJ_OBJ ? '{' : '[';
            for (i = 0; i < count; i++) {
                if (chunks[i]) {
                    if(i) {
                        len = strlen(json);
                        snprintf(json + len, size + 1 - len, ", ");
                    }
                    len = strlen(json);
                    snprintf(json + len, size + 1 - len, "%s", chunks[i]);
                }
            }
            len = strlen(json);
            json[len] = otype == MKJ_OBJ ? '}' : ']';
        }
    } else
        json = NULL;

    /* Free chunks */
    for (i = 0; i < count; i++)
        free(chunks[i]);
    free(chunks);

    return json;
}
