/*
 * kflowd.h
 *
 * Authors: Dirk Tennie <dirk@tarsal.co>
 *          Barrett Lyon <blyon@tarsal.co>
 *
 * Copyright 2024 (c) Tarsal, Inc
 *
 */
#ifndef __KFLOWD_H
#define __KFLOWD_H

/* define minimal kernel requirement */
#define KERNEL_VERSION_MIN 5
#define KERNEL_MAJOR_MIN   10

/* define kernel subsystems and switch */
#define MONITOR_NONE 1
#define MONITOR_FILE 2
#define MONITOR_SOCK 4
#define KPROBE_SWITCH(monitor_type)                                                                                    \
    if (!(monitor & monitor_type))                                                                                     \
        return 0;

/* define file system event values */
#define FS_ACCESS         0x00000001
#define FS_MODIFY         0x00000002
#define FS_ATTRIB         0x00000004
#define FS_CLOSE_WRITE    0x00000008
#define FS_CLOSE_NOWRITE  0x00000010
#define FS_OPEN           0x00000020
#define FS_MOVED_FROM     0x00000040
#define FS_MOVED_TO       0x00000080
#define FS_CREATE         0x00000100
#define FS_DELETE         0x00000200
#define FS_DELETE_SELF    0x00000400
#define FS_MOVE_SELF      0x00000800
#define FS_OPEN_EXEC      0x00001000
#define FS_UNMOUNT        0x00002000
#define FS_Q_OVERFLOW     0x00004000
#define FS_ERROR          0x00008000
#define FS_IN_IGNORED     0x00008000
#define FS_OPEN_PERM      0x00010000
#define FS_ACCESS_PERM    0x00020000
#define FS_OPEN_EXEC_PERM 0x00040000
#define FS_EXCL_UNLINK    0x04000000
#define FS_EVENT_ON_CHILD 0x08000000
#define FS_RENAME         0x10000000
#define FS_DN_MULTISHOT   0x20000000
#define FS_ISDIR          0x40000000
#define FS_IN_ONESHOT     0x80000000 /* only send event once */

/* define file modes */
#define FMODE_READ     0x0000001
#define FMODE_WRITE    0x0000002
#define FMODE_OPENED   0x0080000
#define FMODE_CREATED  0x0100000
#define FMODE_NONOTIFY 0x4000000

/* define dcache types  */
#define DCACHE_ENTRY_TYPE     0x00700000
#define DCACHE_DIRECTORY_TYPE 0x00200000
#define DCACHE_AUTODIR_TYPE   0x00300000

/* define inode mode values */
#define S_IFMT      00170000
#define S_IFSOCK    0140000
#define S_IFLNK     0120000
#define S_IFREG     0100000
#define S_IFBLK     0060000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFIFO     0010000
#define S_ISUID     0004000
#define S_ISGID     0002000
#define S_ISVTX     0001000
#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

/* define event attribute values */
#define ATTR_MODE      (1 << 0)
#define ATTR_UID       (1 << 1)
#define ATTR_GID       (1 << 2)
#define ATTR_SIZE      (1 << 3)
#define ATTR_ATIME     (1 << 4)
#define ATTR_MTIME     (1 << 5)
#define ATTR_CTIME     (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE     (1 << 9)
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE      (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN      (1 << 15)
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_TOUCH     (1 << 17)

/* define file system permission values */
#define USER_READ   256
#define USER_WRITE  128
#define USER_EXE    64
#define GROUP_READ  32
#define GROUP_WRITE 16
#define GROUP_EXE   8
#define OTHER_READ  4
#define OTHER_WRITE 2
#define OTHER_EXE   1

/* define file system permissions */
struct FS_PERM {
    short index;
    short value;
    char  perm;
};

/* define permission index */
enum INDEX_FS_PERM {
    I_USER_READ,
    I_USER_WRITE,
    I_USER_EXE,
    I_GROUP_READ,
    I_GROUP_WRITE,
    I_GROUP_EXE,
    I_OTHER_READ,
    I_OTHER_WRITE,
    I_OTHER_EXE
};

/* define filesystem events */
struct FS_EVENT {
    short index;
    short value;
    char  name[16];
    char  shortname[4];
    char  shortname2[4];
};

/* define filesystem event index */
enum INDEX_FS_EVENT {
    I_CREATE,
    I_OPEN,
    I_OPEN_EXEC,
    I_ACCESS,
    I_ATTRIB,
    I_MODIFY,
    I_CLOSE_WRITE,
    I_CLOSE_NOWRITE,
    I_MOVED_FROM,
    I_MOVED_TO,
    I_DELETE,
    I_DELETE_SELF,
    I_MOVE_SELF,
    I_UNMOUNT,
    I_Q_OVERFLOW
};

/* global instance shared betwwwn user and kernel-side code */
struct FS_EVENT fsevt[] = {{I_CREATE, FS_CREATE, "CREATE", "CRE", "CR"},
                           {I_OPEN, FS_OPEN, "OPEN", "OPN", "OP"},
                           {I_OPEN_EXEC, FS_OPEN_EXEC, "OPEN_EXEC", "OPX", "OX"},
                           {I_ACCESS, FS_ACCESS, "ACCESS", "ACC", "AC"},
                           {I_ATTRIB, FS_ATTRIB, "ATTRIB", "ATT", "AT"},
                           {I_MODIFY, FS_MODIFY, "MODIFY", "MOD", "MO"},
                           {I_CLOSE_WRITE, FS_CLOSE_WRITE, "CLOSE_WRITE", "CLW", "CW"},
                           {I_CLOSE_NOWRITE, FS_CLOSE_NOWRITE, "CLOSE_NOWRITE", "CLN", "CN"},
                           {I_MOVED_FROM, FS_MOVED_FROM, "MOVED_FROM", "MVF", "MF"},
                           {I_MOVED_TO, FS_MOVED_TO, "MOVED_TO", "MVT", "MT"},
                           {I_DELETE, FS_DELETE, "DELETE", "DEL", "DE"},
                           {I_DELETE_SELF, FS_DELETE_SELF, "DELETE_SELF", "DSF", "DS"},
                           {I_MOVE_SELF, FS_MOVE_SELF, "MOVE_SELF", "MSF", "MS"},
                           {I_UNMOUNT, FS_UNMOUNT, "UNMOUNT", "UNM", "UM"},
                           {I_Q_OVERFLOW, FS_Q_OVERFLOW, "Q_OVERFLOW", "QOF", "QO"}};

/* define socket events */
struct SOCK_EVENT {
    short index;
    short value;
    char  name[16];
    char  shortname[4];
};

/* define various non-kernel macros */
#define TOLOWER_STR(str)                                                                                               \
    {                                                                                                                  \
        int cnt;                                                                                                       \
        for (cnt = 0; cnt < (int)strlen(str); cnt++)                                                                   \
            str[cnt] = tolower(str[cnt]);                                                                              \
    }
#define MAX(X, Y)                 (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y)                 (((X) < (Y)) ? (X) : (Y))
#define MAX_STACK_TRACE_DEPTH     16
#define SYS_FILE_JIT_ENABLE       "/proc/sys/net/core/bpf_jit_enable"
#define SYS_FILE_VMLINUX          "/sys/kernel/btf/vmlinux"
#define CACHE_ENTRIES_MAX         65536
#define MAP_RECORDS_MAX           65536
#define MAP_XFILES_MAX            65536
#define MAP_PIDS_MAX              8192
#define MAP_SOCKS_MAX             262144
#define RECORD_SOCK_MAX           5
#define RECORD_TYPE_FILE          1
#define RECORD_TYPE_SOCK          2
#define TASK_COMM_LEN             32
#define TASK_COMM_SHORT_LEN       16
#define DNAME_INLINE_LEN          32
#define VERSION_LEN_MAX           16
#define IF_MAC_LEN_MAX            20
#define IF_INDEX_LEN_MAX          8
#define FILENAME_LEN_MAX          32
#define FILEPATH_LEN_MAX          96
#define FILEPATH_NODE_MAX         16
#define FILE_READ_LEN_MAX         4096
#define FILE_EVENTS_LEN_MAX       256
#define FILE_PERMS_LEN_MAX        32
#define CMD_LEN_MAX               512
#define CMD_OUTPUT_LEN_MAX        1024
#define JSON_OUT_LEN_MAX          8192
#define FS_EVENT_MAX              (int)(sizeof(fsevt) / sizeof(struct FS_EVENT))
#define SOCK_FLAGS_MAX            64
#define SOCK_EXP_MAX              4
#define MODE_LEN_MAX              12
#define DATETIME_LEN_MAX          64
#define DEV_NAME_LEN_MAX          32
#define DEV_FSTYPE_LEN_MAX        8
#define CHECKSUM_TYPE_MD5         0
#define CHECKSUM_TYPE_SHA256      1
#define CACHE_TYPE_USER           0
#define CACHE_TYPE_GROUP          1
#define MD5_DIGEST_STR_LEN        32
#define MD5_DIGEST_LEN            16
#define SHA256_DIGEST_STR_LEN     64
#define SHA256_DIGEST_LEN         32
#define TOKEN_LEN_MAX             64
#define DBG_LEN_MAX               16
#define KEY_PID_INO(p, i)         ((__u64)p << 32 | i)
#define KEY_SOCK(h)               ((__u64)h)
#define GETDEV(dev)               ((__u32)(dev >> 20)) << 8 | ((__u32)(dev & ((1U << 20) - 1)))
#define UDP_MONITOR_STR_LEN       28
#define UDP_MONITOR_OFS           104
#define UDP_SERVER_MAX            8
#define UDP_HOST_DEFAULT          "::FFFF:127.0.0.1"
#define UDP_PORT_DEFAULT          2056
#define TCP_FLAGS_LEN_MAX         256
#define TCP_FLAGS_MAX             (int)(sizeof(tcp_flags) / sizeof(struct TCP_FLAG))
#define HTTP_HEADERS_MAX          32
#define HTTP_HEADER_LEN_MAX       256
#define HTTP_HEADER_SHORT_LEN_MAX 16
#define HTTP_MSG_LEN_MIN          16
#define HTTP_BODY_LEN_MAX         128
#define HTTP_PORT                 80
#define DNS_MSG_LEN_MIN           16
#define DNS_PORT                  53
#define DNS_QNAME_LEN_MAX         128
#define DNS_FLAGS_LEN_MAX         32
#define DNS_RDATA_MAX             8
#define DNS_RDATA_DEC_LEN_MAX     512
#define DNS_QTYPE_MAX             (int)(sizeof(dns_qtypes) / sizeof(struct DNS_QTYPE))

/* define application constants */
enum APP_TYPE { APP_DNS, APP_HTTP, APP_MAX };
#define GET_APP_NAME(type) (type == APP_DNS ? "DNS" : type == APP_HTTP ? "HTTP" : "unknown")
#define APP_MSG_MAX        4
#define APP_MSG_LEN_MIN    MIN(DNS_MSG_LEN_MIN, HTTP_MSG_LEN_MIN)
#define APP_MSG_LEN_MAX    1400
#define APP_PORT_MAX       8

/* define macros for startup requirement checks */
#define CHECK_MAX         3
#define CHECK_MSG_LEN_MAX 64
enum check { c_fail, c_ok, c_warn };

/* define network constants */
#define ETH_HLEN        14
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define AF_INET         2
#define AF_INET6        10
#define IP_ADDR_LEN_MAX 16

/* define ip fragmentation flags */
#define IP_RF      0x8000
#define IP_DF      0x4000
#define IP_MF      0x2000
#define IP_OFFMASK 0x1fff

/* define ipv6 next headers */
#define IPV6_NH_HOP      0
#define IPV6_NH_TCP      6
#define IPV6_NH_UDP      17
#define IPV6_NH_IPV6     41
#define IPV6_NH_ROUTING  43
#define IPV6_NH_FRAGMENT 44
#define IPV6_NH_GRE      47
#define IPV6_NH_ESP      50
#define IPV6_NH_AUTH     51
#define IPV6_NH_ICMP     58
#define IPV6_NH_NONE     59
#define IPV6_NH_DEST     60
#define IPV6_NH_SCTP     132
#define IPV6_NH_MOBILITY 135

/* define udp states */
#define UDP_NONE        0
#define UDP_ESTABLISHED 1
#define UDP_CLOSE       2

/* define socket idle and active timeouts */
#define SOCK_IDLE_TIMEOUT   15
#define SOCK_ACTIVE_TIMEOUT 1800

/* define socket bind locks */
#define SOCK_BINDADDR_LOCK 4
#define SOCK_BINDPORT_LOCK 8

/* define socket buffer constants */
#define SKB_DST_NOREF   1UL
#define SKB_DST_PTRMASK ~(SKB_DST_NOREF)

/* define tcp and udp roles */
enum ROLE { ROLE_NONE, ROLE_TCP_CLIENT, ROLE_TCP_SERVER, ROLE_UDP_CLIENT, ROLE_UDP_SERVER };
#define GET_ROLE_STR(role)                                                                                             \
    (role == ROLE_TCP_CLIENT   ? "tcp client"                                                                          \
     : role == ROLE_TCP_SERVER ? "tcp server"                                                                          \
     : role == ROLE_UDP_CLIENT ? "udp client"                                                                          \
     : role == ROLE_UDP_SERVER ? "udp server"                                                                          \
                               : "unknown")

/* define tcp flags */
#define TCP_NONE 0
#define TCP_FIN  1
#define TCP_SYN  2
#define TCP_RST  4
#define TCP_PSH  8
#define TCP_ACK  16
#define TCP_URG  32
struct TCP_FLAG {
    short id;
    char  flag[4];
} tcp_flags[] = {{TCP_FIN, "FIN"}, {TCP_SYN, "SYN"}, {TCP_RST, "RST"},
                 {TCP_PSH, "PSH"}, {TCP_ACK, "ACK"}, {TCP_URG, "URG"}};

/* define tcp states */
#define TCP_STATE_LEN_MAX 32
char tcp_state_table[][TCP_STATE_LEN_MAX] = {"TCP_NONE",         "TCP_ESTABLISHED", "TCP_SYN_SENT",  "TCP_SYN_RECV",
                                             "TCP_FIN_WAIT1",    "TCP_FIN_WAIT2",   "TCP_TIME_WAIT", "TCP_CLOSE",
                                             "TCP_CLOSE_WAIT",   "TCP_LAST_ACK",    "TCP_LISTEN",    "TCP_CLOSING",
                                             "TCP_NEW_SYN_RECV", "TCP_MAX_STATES"};
/* define dns port and record types */
#define DNS_QTYPE_DEC_LEN_MAX 8
#define DNS_QTYPE_A           1
#define DNS_QTYPE_NS          2
#define DNS_QTYPE_CNAME       5
#define DNS_QTYPE_SOA         6
#define DNS_QTYPE_PTR         12
#define DNS_QTYPE_MX          15
#define DNS_QTYPE_TXT         16
#define DNS_QTYPE_AAAA        28
struct DNS_QTYPE {
    short id;
    char  type[DNS_QTYPE_DEC_LEN_MAX];
} dns_qtypes[] = {{DNS_QTYPE_A, "A"},     {DNS_QTYPE_NS, "NS"}, {DNS_QTYPE_CNAME, "CNAME"}, {DNS_QTYPE_SOA, "SOA"},
                  {DNS_QTYPE_PTR, "PTR"}, {DNS_QTYPE_MX, "MX"}, {DNS_QTYPE_TXT, "TXT"},     {DNS_QTYPE_AAAA, "AAAA"}};

/* define dns class codes */
#define DNS_QCLASS_LEN_MAX 12
#define DNS_QCLASS_MAX     5
#define DNS_QCLASS_NONE    0
#define DNS_QCLASS_IN      1
#define DNS_QCLASS_CS      2
#define DNS_QCLASS_CH      3
#define DNS_QCLASS_HS      4
char dns_qclass_table[][DNS_QCLASS_LEN_MAX] = {"NONE", "IN", "CS", "CH", "HS"};

/* define dns op codes */
#define DNS_OPCODE_LEN_MAX 16
#define DNS_OPCODE_MAX     3
#define DNS_OPCODE_QUERY   0
#define DNS_OPCODE_IQUERY  1
#define DNS_OPCODE_STATUS  2
char dns_opcode_table[][DNS_OPCODE_LEN_MAX] = {"QUERY", "IQUERY", "STATUS"};

/* define dns op codes */
#define DNS_RCODE_LEN_MAX   16
#define DNS_RCODE_MAX       4
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERROR 1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
char dns_rcode_table[][DNS_RCODE_LEN_MAX] = {"NOERROR", "FORMERROR", "SERVFAIL", "NXDOMAIN"};

/* define dns flags */
struct DNS_FLAGS {
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t cd : 1;
    uint8_t ad : 1;
    uint8_t z : 1;
    uint8_t ra : 1;
};

/* define decoded dns message */
struct APP_MSG_DNS {
    uint16_t         transaction_id;
    struct DNS_FLAGS flags;
    uint16_t         qtype;
    uint16_t         qclass;
    char             qname[DNS_QNAME_LEN_MAX];
    uint16_t         qdcount;
    uint16_t         ancount;
    struct {
        uint32_t ttl;
        uint16_t rqtype;
        uint16_t rqclass;
        uint16_t rdlen;
        char     rdata_dec[DNS_RDATA_DEC_LEN_MAX];
        char     rdata_an_dec[DNS_RDATA_DEC_LEN_MAX];
    } an[DNS_RDATA_MAX];
};

/* define decoded http message */
struct APP_MSG_HTTP {
    char     method[HTTP_HEADER_SHORT_LEN_MAX];
    char     url[HTTP_HEADER_LEN_MAX];
    char     version[HTTP_HEADER_SHORT_LEN_MAX];
    uint32_t status;
    char     reason[HTTP_HEADER_LEN_MAX];
    char     header_name[HTTP_HEADERS_MAX][HTTP_HEADER_LEN_MAX];
    char     header_value[HTTP_HEADERS_MAX][HTTP_HEADER_LEN_MAX];
    char     body[HTTP_BODY_LEN_MAX];
};

/* define app message */
struct APP_MSG {
    uint8_t  type;
    uint8_t  cnt;
    uint64_t ts[APP_MSG_MAX];
    uint32_t seq[APP_MSG_MAX];
    uint16_t len[APP_MSG_MAX];
    uint8_t  isrx[APP_MSG_MAX];
    char     data[APP_MSG_MAX][APP_MSG_LEN_MAX];
};

/* define socket info */
struct SOCK_INFO {
    uint32_t       pid;
    uint32_t       tid;
    uint32_t       ppid;
    uint32_t       uid;
    uint32_t       gid;
    uint64_t       ts_proc;
    char           proc[TASK_COMM_SHORT_LEN];
    char           comm[TASK_COMM_LEN];
    char           comm_parent[TASK_COMM_LEN];
    struct sock   *sock;
    uint16_t       tx_ifindex;
    uint64_t       tx_ts_first;
    uint64_t       tx_ts;
    uint32_t       tx_events;
    uint32_t       tx_event[SOCK_FLAGS_MAX];
    uint8_t        tx_flags_map[SOCK_FLAGS_MAX];
    uint8_t        tx_flags_map_cnt;
    uint16_t       rx_ifindex;
    uint64_t       rx_ts_first;
    uint64_t       rx_ts;
    uint32_t       rx_events;
    uint32_t       rx_event[SOCK_FLAGS_MAX];
    uint8_t        rx_flags_map[SOCK_FLAGS_MAX];
    uint8_t        rx_flags_map_cnt;
    uint32_t       rx_ttl;
    uint16_t       family;
    uint8_t        proto;
    uint8_t        state;
    uint8_t        role;
    char           laddr[IP_ADDR_LEN_MAX];
    char           raddr[IP_ADDR_LEN_MAX];
    uint16_t       lport;
    uint16_t       rport;
    uint64_t       ts_first;
    uint32_t       tx_data_packets;
    uint32_t       tx_packets;
    uint32_t       tx_packets_retrans[2];
    uint32_t       tx_packets_dups[2];
    uint64_t       tx_bytes;
    uint64_t       tx_bytes_acked[2];
    uint64_t       tx_bytes_retrans[2];
    uint32_t       tx_rto;
    uint32_t       rx_data_packets;
    uint32_t       rx_packets;
    uint32_t       rx_packets_queued;
    uint32_t       rx_packets_drop[2];
    uint32_t       rx_packets_reorder[2];
    uint32_t       rx_packets_frag;
    uint64_t       rx_bytes;
    uint32_t       rtt;
    struct APP_MSG app_msg;
};

struct SOCK_TUPLE {
    char     laddr[IP_ADDR_LEN_MAX];
    char     raddr[IP_ADDR_LEN_MAX];
    uint16_t lport;
    uint16_t rport;
    uint8_t  proto;
};

/* define socket queue */
struct SOCK_QUEUE {
    uint64_t key;
    uint64_t ts;
};

/* define socket event info */
struct SOCK_EVENT_INFO {
    struct sock    *sock;
    struct sk_buff *skb;
    uint16_t        family;
    uint16_t        lport;
    uint16_t        rport;
    void           *args;
    char            isrx;
    char           *func;
};

/* define filesystem event info for ringbuffer event handler */
struct FS_EVENT_INFO {
    int            index;
    struct dentry *dentry;
    struct dentry *dentry_old;
    char          *func;
};

/* define common record sent to ringbuffer for user */
struct RECORD {
    uint32_t type;
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t age;
    char     proc[TASK_COMM_SHORT_LEN];
    char     comm_parent[TASK_COMM_LEN];
    char     comm[TASK_COMM_LEN];
    uint64_t ts_first;
    uint64_t ts;
};

/* define filesystem record sent to ringbuffer for user */
struct RECORD_FS {
    struct RECORD rc;
    uint32_t      events;
    uint32_t      event[FS_EVENT_MAX];
    uint32_t      ino;
    uint32_t      imode;
    uint32_t      inlink;
    uint32_t      iuid;
    uint32_t      igid;
    uint32_t      idev;
    uint64_t      isize;
    uint64_t      atime_nsec;
    uint64_t      mtime_nsec;
    uint64_t      ctime_nsec;
    uint64_t      mtime_nsec_first;
    uint64_t      isize_first;
    char          filepath[FILEPATH_LEN_MAX];
    union {
        struct {
            char filename_from[FILENAME_LEN_MAX / 2];
            char filename_to[FILENAME_LEN_MAX / 2];
        };
        char filename[FILENAME_LEN_MAX];
    };
};

/* define aggregated socket record sent to ringbuffer for user */
struct RECORD_SOCK {
    struct RECORD  rc;
    uint8_t        tx_flags[SOCK_FLAGS_MAX];
    uint32_t       tx_events;
    uint32_t       tx_event[SOCK_FLAGS_MAX];
    uint64_t       tx_ts_first;
    uint64_t       tx_ts;
    uint8_t        rx_flags[SOCK_FLAGS_MAX];
    uint32_t       rx_event[SOCK_FLAGS_MAX];
    uint32_t       rx_events;
    uint64_t       rx_ts_first;
    uint64_t       rx_ts;
    uint16_t       family;
    uint8_t        proto;
    uint8_t        state;
    uint8_t        role;
    char           laddr[IP_ADDR_LEN_MAX];
    char           raddr[IP_ADDR_LEN_MAX];
    uint16_t       lport;
    uint16_t       rport;
    uint16_t       tx_ifindex;
    uint32_t       tx_data_packets;
    uint32_t       tx_packets;
    uint32_t       tx_packets_retrans;
    uint32_t       tx_packets_dups;
    uint64_t       tx_bytes;
    uint64_t       tx_bytes_acked;
    uint64_t       tx_bytes_retrans;
    uint32_t       tx_rto;
    uint16_t       rx_ifindex;
    uint32_t       rx_data_packets;
    uint32_t       rx_packets;
    uint32_t       rx_packets_queued;
    uint32_t       rx_packets_drop;
    uint32_t       rx_packets_reorder;
    uint32_t       rx_packets_frag;
    uint64_t       rx_bytes;
    uint32_t       rx_ttl;
    uint32_t       rtt;
    struct APP_MSG app_msg;
};

/* define ringbuffer stats collected on records */
struct STATS {
    uint64_t fs_records;
    uint64_t fs_records_deleted;
    uint64_t fs_records_dropped;
    uint64_t fs_records_rb_max;
    uint64_t fs_events;
    uint64_t q_push_added;
    uint64_t q_push_updated;
    uint64_t q_push_readded;
    uint64_t q_pop_expired;
    uint64_t q_pop_ignored;
    uint64_t q_pop_missed;
};

/* define version info for executable files */
struct XFILES {
    char    *package;
    char    *version;
    char    *md5;
    char    *sha256;
    uint64_t size;
    uint32_t mtime;
    int      truncated;
};

/* define plugins types, functions and search path */
enum PLUGIN_TYPE { P_DNS, P_HTTP, P_VIRUS, P_VULN, P_DEVICE, P_INTERFACE, P_USER_GROUP, P_MAX };
typedef int (*plugin_func)();
typedef int plugin_dns_func(char *, int, struct APP_MSG_DNS *);
typedef int plugin_http_func(char *, int, struct APP_MSG_HTTP *);
typedef int plugin_virus_func(int, const char *, const char *, char *);
struct bpf_map; /* eliminate compiler warning */
typedef int plugin_vuln_func(struct bpf_map *, int *, char *, int, char *);
typedef int plugin_device_func(char **, char **);
typedef int plugin_interface_func(char **);
typedef int plugin_user_group_func(int, char **);
#define PLUGIN_PATH         "../lib/"

/* define output types */
#define JSON_SUB_KEY_MAX    16
#define JSON_KEY_LEN_MAX    32
#define JSON_LEGEND_LEN_MAX 128
#define JSON_TYPE_MAX       3
#define JSON_FULL           0
#define JSON_MIN            1
#define TABLE_OUTPUT        2

/* define json key */
struct JSON_KEY {
    int  index;
    char jtypekey[JSON_TYPE_MAX][JSON_KEY_LEN_MAX];
    char jlegend[JSON_LEGEND_LEN_MAX];
};

/* define json sub key */
struct JSON_SUB_KEY {
    int index;
    struct {
        char jkey[JSON_KEY_LEN_MAX];
        char jlegend[JSON_LEGEND_LEN_MAX];
    } sub[JSON_SUB_KEY_MAX];
};

/* define json key index */
enum INDEX_JSON_KEY {
    I_INFO_SEQUENCE_NUMBER,
    I_INFO_TIMESTAMP,
    I_INFO_MONITOR,
    I_INFO_HOST_NAME,
    I_INFO_HOST_IP,
    I_INFO_HOST_TOKEN,
    I_INFO_SYSTEM,
    I_INFO_KERNEL,
    I_INFO_VERSION,
    I_INFO_UPTIME,
    I_PROC_PARENT,
    I_PROC,
    I_PROC_VERSION,
    I_PROC_USER,
    I_PROC_GROUP,
    I_PROC_PPID,
    I_PROC_PID,
    I_PROC_TID,
    I_PROC_UID,
    I_PROC_GID,
    I_PROC_AGE,
    I_FILE_PATH,
    I_FILE,
    I_FILE_ORIGIN,
    I_FILE_VERSION,
    I_FILE_MODE,
    I_FILE_EVENT_COUNT,
    I_FILE_EVENTS,
    I_FILE_EVENTS_DURATION,
    I_FILE_INODE,
    I_FILE_INODE_LINK_COUNT,
    I_FILE_DEVICE,
    I_FILE_PERMISSIONS,
    I_FILE_USER,
    I_FILE_GROUP,
    I_FILE_UID,
    I_FILE_GID,
    I_FILE_SIZE,
    I_FILE_SIZE_CHANGE,
    I_FILE_ACCESS_TIME,
    I_FILE_STATUS_CHANGE_TIME,
    I_FILE_MODIFICATION_TIME,
    I_FILE_MODIFICATION_TIME_CHANGE,
    I_FILE_CHECKSUM_MD5,
    I_FILE_CHECKSUM_SHA256,
    I_SOCK_PROTOCOL,
    I_SOCK_ROLE,
    I_SOCK_STATE,
    I_SOCK_FAMILY,
    I_SOCK_LOCAL_IP,
    I_SOCK_LOCAL_PORT,
    I_SOCK_REMOTE_IP,
    I_SOCK_REMOTE_PORT,
    I_SOCK_TX_INTERFACE,
    I_SOCK_TX_DATA_PACKETS,
    I_SOCK_TX_PACKETS,
    I_SOCK_TX_PACKETS_RETRANS,
    I_SOCK_TX_PACKETS_DUPS,
    I_SOCK_TX_FLAGS,
    I_SOCK_TX_DURATION,
    I_SOCK_TX_BYTES,
    I_SOCK_TX_BYTES_ACKED,
    I_SOCK_TX_BYTES_RETRANS,
    I_SOCK_TX_RTO,
    I_SOCK_RX_INTERFACE,
    I_SOCK_RX_DATA_PACKETS,
    I_SOCK_RX_PACKETS,
    I_SOCK_RX_PACKETS_QUEUED,
    I_SOCK_RX_PACKETS_DROP,
    I_SOCK_RX_PACKETS_REORDER,
    I_SOCK_RX_PACKETS_FRAG,
    I_SOCK_RX_FLAGS,
    I_SOCK_RX_DURATION,
    I_SOCK_RX_BYTES,
    I_SOCK_RX_TTL,
    I_SOCK_RTT,
    I_SOCK_AGE,
    I_APP,
    I_APP_TX_DNS,
    I_APP_RX_DNS,
    I_APP_TX_HTTP,
    I_APP_RX_HTTP
};

/* JSON macro to get key */
#define JKEY(i) jkey[i].jtypekey[0]

/* JSON container types */
enum MKJSON_CONTAINER_TYPE { MKJ_ARR, MKJ_OBJ };

/* JSON data types */
enum MKJSON_VALUE_TYPE {
    J_STRING,
    J_TIMESTAMP,
    J_JSON,
    J_JSON_FREE,
    J_INT,
    J_LLINT,
    J_UINT,
    J_LLUINT,
    J_DOUBLE,
    J_LDOUBLE,
    J_SCI_DOUBLE,
    J_SCI_LDOUBLE,
    J_BOOL,
    J_NULL,
    J_IGN_STRING,
    J_IGN_TIMESTAMP,
    J_IGN_JSON,
    J_IGN_INT,
    J_IGN_LLINT,
    J_IGN_UINT,
    J_IGN_LLUINT,
    J_IGN_DOUBLE,
    J_IGN_LDOUBLE,
    J_IGN_BOOL,
    J_IGN_NULL
};

/* define json output messages  */
enum JSON_OBJ {
    J_INFO,
    J_PROC,
    J_SOCK,
    J_SOCK_CLIENT_TX,
    J_SOCK_CLIENT_RX,
    J_SOCK_SERVER_RX,
    J_SOCK_SERVER_TX,
    J_SOCK_AGE,
    J_FILE,
    J_FILE_CHECKSUM,
    J_APP,
    J_APP_CLIENT_TX_DNS,
    J_APP_CLIENT_RX_DNS,
    J_APP_CLIENT_TX_HTTP,
    J_APP_CLIENT_RX_HTTP,
    J_APP_SERVER_RX_DNS,
    J_APP_SERVER_TX_DNS,
    J_APP_SERVER_RX_HTTP,
    J_APP_SERVER_TX_HTTP,
    JSON_OBJ_MAX
};

/* hash functions */
const uint64_t crc64_tab[256] = {
    0x0000000000000000UL, 0x7ad870c830358979UL, 0xf5b0e190606b12f2UL, 0x8f689158505e9b8bUL, 0xc038e5739841b68fUL,
    0xbae095bba8743ff6UL, 0x358804e3f82aa47dUL, 0x4f50742bc81f2d04UL, 0xab28ecb46814fe75UL, 0xd1f09c7c5821770cUL,
    0x5e980d24087fec87UL, 0x24407dec384a65feUL, 0x6b1009c7f05548faUL, 0x11c8790fc060c183UL, 0x9ea0e857903e5a08UL,
    0xe478989fa00bd371UL, 0x7d08ff3b88be6f81UL, 0x07d08ff3b88be6f8UL, 0x88b81eabe8d57d73UL, 0xf2606e63d8e0f40aUL,
    0xbd301a4810ffd90eUL, 0xc7e86a8020ca5077UL, 0x4880fbd87094cbfcUL, 0x32588b1040a14285UL, 0xd620138fe0aa91f4UL,
    0xacf86347d09f188dUL, 0x2390f21f80c18306UL, 0x594882d7b0f40a7fUL, 0x1618f6fc78eb277bUL, 0x6cc0863448deae02UL,
    0xe3a8176c18803589UL, 0x997067a428b5bcf0UL, 0xfa11fe77117cdf02UL, 0x80c98ebf2149567bUL, 0x0fa11fe77117cdf0UL,
    0x75796f2f41224489UL, 0x3a291b04893d698dUL, 0x40f16bccb908e0f4UL, 0xcf99fa94e9567b7fUL, 0xb5418a5cd963f206UL,
    0x513912c379682177UL, 0x2be1620b495da80eUL, 0xa489f35319033385UL, 0xde51839b2936bafcUL, 0x9101f7b0e12997f8UL,
    0xebd98778d11c1e81UL, 0x64b116208142850aUL, 0x1e6966e8b1770c73UL, 0x8719014c99c2b083UL, 0xfdc17184a9f739faUL,
    0x72a9e0dcf9a9a271UL, 0x08719014c99c2b08UL, 0x4721e43f0183060cUL, 0x3df994f731b68f75UL, 0xb29105af61e814feUL,
    0xc849756751dd9d87UL, 0x2c31edf8f1d64ef6UL, 0x56e99d30c1e3c78fUL, 0xd9810c6891bd5c04UL, 0xa3597ca0a188d57dUL,
    0xec09088b6997f879UL, 0x96d1784359a27100UL, 0x19b9e91b09fcea8bUL, 0x636199d339c963f2UL, 0xdf7adabd7a6e2d6fUL,
    0xa5a2aa754a5ba416UL, 0x2aca3b2d1a053f9dUL, 0x50124be52a30b6e4UL, 0x1f423fcee22f9be0UL, 0x659a4f06d21a1299UL,
    0xeaf2de5e82448912UL, 0x902aae96b271006bUL, 0x74523609127ad31aUL, 0x0e8a46c1224f5a63UL, 0x81e2d7997211c1e8UL,
    0xfb3aa75142244891UL, 0xb46ad37a8a3b6595UL, 0xceb2a3b2ba0eececUL, 0x41da32eaea507767UL, 0x3b024222da65fe1eUL,
    0xa2722586f2d042eeUL, 0xd8aa554ec2e5cb97UL, 0x57c2c41692bb501cUL, 0x2d1ab4dea28ed965UL, 0x624ac0f56a91f461UL,
    0x1892b03d5aa47d18UL, 0x97fa21650afae693UL, 0xed2251ad3acf6feaUL, 0x095ac9329ac4bc9bUL, 0x7382b9faaaf135e2UL,
    0xfcea28a2faafae69UL, 0x8632586aca9a2710UL, 0xc9622c4102850a14UL, 0xb3ba5c8932b0836dUL, 0x3cd2cdd162ee18e6UL,
    0x460abd1952db919fUL, 0x256b24ca6b12f26dUL, 0x5fb354025b277b14UL, 0xd0dbc55a0b79e09fUL, 0xaa03b5923b4c69e6UL,
    0xe553c1b9f35344e2UL, 0x9f8bb171c366cd9bUL, 0x10e3202993385610UL, 0x6a3b50e1a30ddf69UL, 0x8e43c87e03060c18UL,
    0xf49bb8b633338561UL, 0x7bf329ee636d1eeaUL, 0x012b592653589793UL, 0x4e7b2d0d9b47ba97UL, 0x34a35dc5ab7233eeUL,
    0xbbcbcc9dfb2ca865UL, 0xc113bc55cb19211cUL, 0x5863dbf1e3ac9decUL, 0x22bbab39d3991495UL, 0xadd33a6183c78f1eUL,
    0xd70b4aa9b3f20667UL, 0x985b3e827bed2b63UL, 0xe2834e4a4bd8a21aUL, 0x6debdf121b863991UL, 0x1733afda2bb3b0e8UL,
    0xf34b37458bb86399UL, 0x8993478dbb8deae0UL, 0x06fbd6d5ebd3716bUL, 0x7c23a61ddbe6f812UL, 0x3373d23613f9d516UL,
    0x49aba2fe23cc5c6fUL, 0xc6c333a67392c7e4UL, 0xbc1b436e43a74e9dUL, 0x95ac9329ac4bc9b5UL, 0xef74e3e19c7e40ccUL,
    0x601c72b9cc20db47UL, 0x1ac40271fc15523eUL, 0x5594765a340a7f3aUL, 0x2f4c0692043ff643UL, 0xa02497ca54616dc8UL,
    0xdafce7026454e4b1UL, 0x3e847f9dc45f37c0UL, 0x445c0f55f46abeb9UL, 0xcb349e0da4342532UL, 0xb1eceec59401ac4bUL,
    0xfebc9aee5c1e814fUL, 0x8464ea266c2b0836UL, 0x0b0c7b7e3c7593bdUL, 0x71d40bb60c401ac4UL, 0xe8a46c1224f5a634UL,
    0x927c1cda14c02f4dUL, 0x1d148d82449eb4c6UL, 0x67ccfd4a74ab3dbfUL, 0x289c8961bcb410bbUL, 0x5244f9a98c8199c2UL,
    0xdd2c68f1dcdf0249UL, 0xa7f41839ecea8b30UL, 0x438c80a64ce15841UL, 0x3954f06e7cd4d138UL, 0xb63c61362c8a4ab3UL,
    0xcce411fe1cbfc3caUL, 0x83b465d5d4a0eeceUL, 0xf96c151de49567b7UL, 0x76048445b4cbfc3cUL, 0x0cdcf48d84fe7545UL,
    0x6fbd6d5ebd3716b7UL, 0x15651d968d029fceUL, 0x9a0d8ccedd5c0445UL, 0xe0d5fc06ed698d3cUL, 0xaf85882d2576a038UL,
    0xd55df8e515432941UL, 0x5a3569bd451db2caUL, 0x20ed197575283bb3UL, 0xc49581ead523e8c2UL, 0xbe4df122e51661bbUL,
    0x3125607ab548fa30UL, 0x4bfd10b2857d7349UL, 0x04ad64994d625e4dUL, 0x7e7514517d57d734UL, 0xf11d85092d094cbfUL,
    0x8bc5f5c11d3cc5c6UL, 0x12b5926535897936UL, 0x686de2ad05bcf04fUL, 0xe70573f555e26bc4UL, 0x9ddd033d65d7e2bdUL,
    0xd28d7716adc8cfb9UL, 0xa85507de9dfd46c0UL, 0x273d9686cda3dd4bUL, 0x5de5e64efd965432UL, 0xb99d7ed15d9d8743UL,
    0xc3450e196da80e3aUL, 0x4c2d9f413df695b1UL, 0x36f5ef890dc31cc8UL, 0x79a59ba2c5dc31ccUL, 0x037deb6af5e9b8b5UL,
    0x8c157a32a5b7233eUL, 0xf6cd0afa9582aa47UL, 0x4ad64994d625e4daUL, 0x300e395ce6106da3UL, 0xbf66a804b64ef628UL,
    0xc5bed8cc867b7f51UL, 0x8aeeace74e645255UL, 0xf036dc2f7e51db2cUL, 0x7f5e4d772e0f40a7UL, 0x05863dbf1e3ac9deUL,
    0xe1fea520be311aafUL, 0x9b26d5e88e0493d6UL, 0x144e44b0de5a085dUL, 0x6e963478ee6f8124UL, 0x21c640532670ac20UL,
    0x5b1e309b16452559UL, 0xd476a1c3461bbed2UL, 0xaeaed10b762e37abUL, 0x37deb6af5e9b8b5bUL, 0x4d06c6676eae0222UL,
    0xc26e573f3ef099a9UL, 0xb8b627f70ec510d0UL, 0xf7e653dcc6da3dd4UL, 0x8d3e2314f6efb4adUL, 0x0256b24ca6b12f26UL,
    0x788ec2849684a65fUL, 0x9cf65a1b368f752eUL, 0xe62e2ad306bafc57UL, 0x6946bb8b56e467dcUL, 0x139ecb4366d1eea5UL,
    0x5ccebf68aecec3a1UL, 0x2616cfa09efb4ad8UL, 0xa97e5ef8cea5d153UL, 0xd3a62e30fe90582aUL, 0xb0c7b7e3c7593bd8UL,
    0xca1fc72bf76cb2a1UL, 0x45775673a732292aUL, 0x3faf26bb9707a053UL, 0x70ff52905f188d57UL, 0x0a2722586f2d042eUL,
    0x854fb3003f739fa5UL, 0xff97c3c80f4616dcUL, 0x1bef5b57af4dc5adUL, 0x61372b9f9f784cd4UL, 0xee5fbac7cf26d75fUL,
    0x9487ca0fff135e26UL, 0xdbd7be24370c7322UL, 0xa10fceec0739fa5bUL, 0x2e675fb4576761d0UL, 0x54bf2f7c6752e8a9UL,
    0xcdcf48d84fe75459UL, 0xb71738107fd2dd20UL, 0x387fa9482f8c46abUL, 0x42a7d9801fb9cfd2UL, 0x0df7adabd7a6e2d6UL,
    0x772fdd63e7936bafUL, 0xf8474c3bb7cdf024UL, 0x829f3cf387f8795dUL, 0x66e7a46c27f3aa2cUL, 0x1c3fd4a417c62355UL,
    0x935745fc4798b8deUL, 0xe98f353477ad31a7UL, 0xa6df411fbfb21ca3UL, 0xdc0731d78f8795daUL, 0x536fa08fdfd90e51UL,
    0x29b7d047efec8728UL};

static inline uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l) {
    uint64_t j;
    for (j = 0; j < l; j++) {
        uint8_t byte = s[j];
        uint8_t i = (uint8_t)crc ^ byte;
        crc = crc64_tab[i] ^ (crc >> 8);
    }
    return crc;
}

#endif /* __KFLOWD_H */
