<div align="right">
<a href="#" target="_blank"><img src="https://img.shields.io/endpoint?url=https://kflowd.github.io/kflowd/gh-stats-version.json"/></a>
<a href="https://github.com/kflowd/kflowd/actions/workflows/kflowd-ci.yml" target="_blank"><img src="https://github.com/kflowd/kflowd/actions/workflows/kflowd-ci.yml/badge.svg"/></a>
<a href="#license" target="_blank"><img src="https://img.shields.io/badge/License-GPL_v2-lightgrey.svg"/></a>
</div>

<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/108887718/211927677-8de51731-1bed-4091-8475-954da95b845d.png" align="left" width="80px"/>
<img src="https://user-images.githubusercontent.com/108887718/217375605-b22fff83-abc5-4244-b36d-34989ed209a9.png" align="left" width="80px"/>
</picture>

## Kernel-based Process Monitoring on Linux Endpoints via eBPF

### kflowd runs as agent on Linux endpoints to monitor processes via eBPF kernel subsystem for filesystem and TCP and UDP networking events to enable immediate threat and anomaly detection on suspicious activities.
#### Advanced non-ebpf related features as DNS and HTTP application messsage decoding, checksum calculation for virus detection, process and file versioning for vulnerability detection and file device, network interface and user-group identification for files and processes can be enabled via open-binary plugin modules.

kflowd contains an eBPF program running in kernel context and its control application running in userspace.<br>
The eBPF program traces kernel functions to monitor processes based on file system and networking events. Events are aggregated into records and submitted into a ringbuffer where they are polled by the userspace control application. All Records are enriched with process information and then converted into a message in JSON output format.<br>
Final messages are printed to stdout console and can be sent via UDP protocol to specified hosts for post-processing in the cloud.

kflowd runs on Linux kernels 5.10+ and is built with the **libbpf+CO-RE** (Compile-Once-Run-Everywhere) eBPF development toolchain using **BTF** (BPF Type Format) to allow portability by avoiding dependencies on differences in kernel headers between kernel versions on deployment.

### JSON Output

kflowd outputs JSON messages generated for each record of aggregated file system and TCP, UDP networking events and optionally DNS and HTTP application messages in the formats as shown in the following examples:

<details open>
<summary>&nbsp;Filesystem Record</summary>

```
{
  "InfoSequenceNumber": 1,
  "InfoTimestamp": "Thu, Apr 04 2024 15:34:35.643031330 UTC",
  "InfoMonitor": "filesystem",
  "InfoHostName": "dev.kflow.co",
  "InfoHostIP": "38.110.1.24",
  "InfoSystem": "Linux",
  "InfoKernel": "6.1.0-10-amd64",
  "InfoVersion": "kflowd-v1.2.50",
  "InfoUptime": 21.262713426,
  "ProcParent": "sshd",
  "Proc": "sftp-server",
  "ProcVersion": "1:9.2p1-2+deb12u1",
  "ProcUser": "dirk",
  "ProcGroup": "dirk",
  "ProcPPID": 183546,
  "ProcPID": 183547,
  "ProcTID": 183547,
  "ProcUID": 1002,
  "ProcGID": 1002,
  "ProcAge": 2.408293862,
  "FilePath": "/home/dirk/",
  "File": "malware",
  "FileVersion": "0.9",
  "FileMode": "regular",
  "FileEventCount": 4,
  "FileEvents": {
    "OPEN": 1,
    "MODIFY": 2,
    "CLOSE_WRITE": 1
  },
  "FileEventsDuration": 0.811829334,
  "FileInode": 19567988,
  "FileInodeLinkCount": 1,
  "FileDevice": "902h:/dev/md2:/:ext4",
  "FilePermissions": "0755/-rwxr-xr-x",
  "FileUser": "dirk",
  "FileGroup": "dirk",
  "FileUID": 1002,
  "FileGID": 1002,
  "FileSize": 41,
  "FileSizeChange": 41,
  "FileAccessTime": "Thu, Apr 04 2024 15:12:01.435718956 UTC",
  "FileStatusChangeTime": "Thu, Apr 04 2024 15:34:35.154106191 UTC",
  "FileModificationTime": "Thu, Apr 04 2024 15:34:35.154106191 UTC",
  "FileModificationTimeChange": 0.327993681,
  "FileMD5": "96760f46bd29ba986279f22bed9839f5",
  "FileSHA256": "72c58c2d02ae3a87f521594373433b7d05477c4994fc0ab4376827cadb29ba7e"
}
```
</details>

<details open>
<summary>&nbsp;UDP + DNS Networking Record</summary>

```
{
  "InfoSequenceNumber": 2,
  "InfoTimestamp": "Thu, Apr 04 2024 15:39:11.463732866 UTC",
  "InfoMonitor": "socket",
  "InfoHostName": "dev.kflow.co",
  "InfoHostIP": "38.110.1.24",
  "InfoSystem": "Linux",
  "InfoKernel": "6.1.0-10-amd64",
  "InfoVersion": "kflowd-v1.2.50",
  "InfoUptime": 23.972984597,
  "ProcParent": "bash",
  "Proc": "curl",
  "ProcVersion": "7.45.2-3",
  "ProcUser": "dirk",
  "ProcGroup": "dirk",
  "ProcPPID": 199853,
  "ProcPID": 199856,
  "ProcTID": 199857,
  "ProcUID": 1002,
  "ProcGID": 1002,
  "ProcAge": 0.044454620,
  "SockProtocol": "UDP",
  "SockRole": "CLIENT",
  "SockState": "UDP_ESTABLISHED",
  "SockFamily": "AF_INET",
  "SockLocalIP": "38.110.1.24",
  "SockLocalPort": 56664,
  "SockRemoteIP": "8.8.4.4",
  "SockRemotePort": 53,
  "SockTxInterface": "4:enp5s0:0c:c4:7a:88:84:c2",
  "SockTxPackets": 2,
  "SockTxDuration": 0.000048490,
  "SockTxBytes": 52,
  "SockTxInterface": "4:enp5s0:0c:c4:7a:88:84:c2",
  "SockRxPackets": 2,
  "SockRxPacketsQueued": 0,
  "SockRxPacketsDrop": 0,
  "SockRxPacketsFrag": 0,
  "SockRxDuration": 22.475134750,
  "SockRxBytes": 155,
  "SockRxTTL": 125,
  "SockAge": 0.043689149,
  "App": "DNS",
  "AppTxDns": [{
    "_Timestamp": 0.000001177,
    "TransactionId": 56864,
    "OpCode": "QUERY",
    "Flags": ["RD"],
    "ResourceRecords": [
      ["A", "kflow.co"]
    ]
  },
  {
    "_Timestamp": 0.000048627,
    "TransactionId": 52515,
    "OpCode": "QUERY",
    "Flags": ["RD"],
    "ResourceRecords": [
      ["AAAA", "kflow.co"]
    ]
  }],
  "AppRxDns": [{
    "_Timestamp": 0.037965555,
    "TransactionId": 52515,
    "ResponseCode": "NOERROR",
    "Flags": ["QR", "RD", "RA"],
    "AnswerCount": 0,
    "ResourceRecords": []
  },
  {
    "_Timestamp": 0.043688644,
    "TransactionId": 56864,
    "ResponseCode": "NOERROR",
    "Flags": ["QR", "RD", "RA"],
    "AnswerCount": 2,
    "ResourceRecords": [
      ["A", "kflow.co", 600, "IN", "15.197.142.173"],
      ["A", "kflow.co", 600, "IN", "3.33.152.147"]
    ]
  }]
}
```
</details>

<details open>
<summary>&nbsp;TCP + HTTP Networking Record</summary>

```
{
  "InfoSequenceNumber": 3,
  "InfoTimestamp": "Thu, Apr 04 2024 15:39:11.928989997 UTC",
  "InfoMonitor": "socket",
  "InfoHostName": "dev.kflow.co",
  "InfoHostIP": "38.110.1.24",
  "InfoSystem": "Linux",
  "InfoKernel": "6.1.0-10-amd64",
  "InfoVersion": "kflowd-v1.2.50",
  "InfoUptime": 24.873001288,
  "ProcParent": "bash",
  "Proc": "curl",
  "ProcVersion": "7.45.2-3",
  "ProcUser": "dirk",
  "ProcGroup": "dirk",
  "ProcPPID": 199853,
  "ProcPID": 216998,
  "ProcTID": 216998,
  "ProcUID": 1002,
  "ProcGID": 1002,
  "ProcAge": 0.114196829,
  "SockProtocol": "TCP",
  "SockRole": "CLIENT",
  "SockState": "TCP_CLOSE",
  "SockFamily": "AF_INET",
  "SockLocalIP": "38.110.1.24",
  "SockLocalPort": 43302,
  "SockRemoteIP": "15.197.142.173",
  "SockRemotePort": 80,
  "SockTxInterface": "4:enp5s0:0c:c4:7a:88:84:c2",
  "SockTxDataPackets": 1,
  "SockTxPackets": 6,
  "SockTxPacketsRetrans": 0,
  "SockTxPacketsDups": 0,
  "SockTxFlags": {
    "SYN": 1,
    "ACK": 3,
    "PSH-ACK": 1,
    "FIN-ACK": 1
  },
  "SockTxDuration": 0.057274799,
  "SockTxBytes": 72,
  "SockTxBytesAcked": 74,
  "SockTxBytesRetrans": 0,
  "SockTxRTO": 51,
  "SockTxInterface": "4:enp5s0:0c:c4:7a:88:84:c2",
  "SockRxDataPackets": 1,
  "SockRxPackets": 4,
  "SockRxPacketsQueued": 0,
  "SockRxPacketsDrop": 0,
  "SockRxPacketsReorder": 0,
  "SockRxPacketsFrag": 0,
  "SockRxFlags": {
    "SYN-ACK": 1,
    "ACK": 1,
    "PSH-ACK": 1,
    "FIN-ACK": 1
  },
  "SockRxDuration": 0.057197399,
  "SockRxBytes": 342,
  "SockRxTTL": 185,
  "SockRTT": 0.000450625,
  "SockAge": 0.057344028,
  "App": "HTTP",
  "AppTxHttp": [{
    "_Timestamp": 0.000876589,
    "_Method": "GET",
    "_Url": "/",
    "_Version": "HTTP/1.1",
    "Host": "kflow.co",
    "User-Agent": "curl/7.88.1",
    "Accept": "*/*"
  }],
  "AppRxHttp": [{
    "_Timestamp": 0.056237469,
    "_Version": "HTTP/1.1",
    "_Status": 301,
    "_Reason": "Moved Permanently",
    "Date": "Thu, 04 Apr 2024 15:49:12 GMT",
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": "59",
    "Connection": "keep-alive",
    "Location": "https://kflowd.github.io",
    "Server": "ip-10-123-123-119.ec2.internal",
    "X-Request-Id": "5c331cbe-fbe1-40ea-ba2b-989691e687a0",
    "_Body": "<a href=\"https://kflowd.github.io\">Moved Permanently</a>."
  }]
}
```
</details>

### Runtime Requirements
Kernel 5.10+ compiled with:
- CONFIG_BPF=y
- CONFIG_KPROBES=y
- CONFIG_KRETPROBES=y
- CONFIG_DEBUG_INFO_BTF=y
- Maps (since 4.1+) to perform filesystem event aggregation in hash tables
- Ringbuffer (since 5.8+) to share data between kernel eBPF program and user-space application
- Global variables (since 5.5) for parameterization of application behavior
- vmlinux.h file in binary form at /sys/kernel/btf/vmlinux
- Libraries libelf and libz installed

### Runtime Performance Recommendations
Kernel 5.10+ compiled with Just-In-Time eBPF compiler (JIT):
- CONFIG_BPF_JIT=y

JIT system control settings enabled:
- net.core.bpf_jit_enable=1

The following link provides an overview of Linux distributions with eBPF CO-RE & BTF enabled by default:<br>
**[Linux Distributions w/ eBPF CO-RE & BTF](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)**

For high performance UDP output the following kernel network settings are recommended:
- sysctl -w net.core.rmem_max=134217728
- sysctl -w net.core.wmem_max=134217728

### Runtime Options
```
Usage:
  kflowd [-m file,socket] [-t IDLE,ACTIVE] [-e EVENTS] [-o json|table] [-v] [-c]
         [-p dns=PROTO/PORT,...] [-p http=PROTO/PORT,...] [-u IP:PORT] [-q] [-d] [-V]
         [-T TOKEN] [-D PROCESS], [-l] [--legend], [-h] [--help], [--version]
  -m file,socket          Monitor only specified kernel subsystem (filesystem or sockets)
                            (default: all, option omitted!)
  -t IDLE,ACTIVE          Timeout in seconds for idle or active network sockets until export
                            (default: idle '15' seconds, active '1800' seconds)
  -e EVENTS               Max number of filesystem events per aggregated record until export
                            (default: disabled, '1': no aggregation)
  -o json                 Json output with formatting (default)
     json-min             Json output with minimal formatting
     table                Tabular output with limited keys and no UDP output
  -v                      Version of executable files identified by installed package
                            (supported only for rpm- and deb-based package management)
  -c                      Checksum hashes of MD5 and SHA256 calculated for executables
  -p dns=PROTO/PORT,...   Port(s) examined for decoding of DNS application protocol
                            (default: dns=udp/53,tcp/53, disabled: dns=off)
  -p http=PROTO/PORT,...  Port(s) examined for decoding of HTTP application protocol
                            (default: http=tcp/80, disabled: http=off)
  -u IP:PORT,...          UDP server(s) IPv4 or IPv6 address to send json output to.
                          Output also printed to stdout console unless quiet option -q or
                            daemon mode -d specified
  -q                      Quiet mode to suppress output to stdout console
  -d                      Daemonize program to run in background
  -V                      Verbose output
                            Print eBPF load and co-re messages on start of eBPF program
                            to stderr console
  -T TOKEN                Token specified on host to be included in json output
  -l, --legend            Show legend
  -h, --help              Show help
      --version           Show version
  -D PROCESS              Debug
                            Print ebpf kernel log messages of process or expiration queue to
                            kernel trace pipe (any process: '*', with quotes!, queue: 'q')
                            Use command:
                              'sudo cat /sys/kernel/debug/tracing/trace_pipe'

Examples:
  sudo ./kflowd                                                           # terminal mode
  sudo ./kflowd -m file,socket -v -c -u 1.2.3.4:2056,127.0.0.1:2057 -d    # daemon mode
  sudo ./kflowd -m socket -v -c -u 1.2.3.4:2056 -V -D '*'                 # debug mode
  sudo ./kflowd --legend                                                  # show legend
  sudo ./kflowd --version                                                 # show version
```

### Build Requirements
- Kernel version 5.10+ compiled with BTF for CO-RE:
  ```
  uname -a
  cat /boot/config-* | grep CONFIG_DEBUG_INFO_BTF
  ```
- BPF enabled in file /etc/sysctl.conf:
  ```
  ...
  kernel.bpf_stats_enabled=1
  kernel.unprivileged_bpf_disabled=0
  ```

### Build Prerequisites
- Debian-based (Ubuntu, Mint)

    - Install libraries:
      ```
      sudo apt install libz-dev
      sudo apt install libelf-dev
      sudo apt install libcap-dev
      sudo apt install libbfd-dev
      sudo apt install libc6-dev-i386
      ```
    - Install Clang 16+ toolchain:
      ```
      sudo apt install build-essential
      sudo apt install pkg-config
      sudo apt install clang-16*
      sudo apt install llvm-16*
      sudo ln -s /usr/bin/clang-16 /usr/bin/clang
      sudo ln -s /usr/bin/llvm-strip-16 /usr/bin/llvm-strip
      ```
- Redhat-based (Amazon Linux, Fedora)

    - Install libraries:
      ```
      sudo yum install zlib-devel
      sudo yum install elfutils-libelf-devel
      sudo yum install libcap-devel
      sudo yum install binutils-devel
      sudo yum install glibc-devel.i386 or .i686
      ```
    - Install Clang 16+ toolchain:
      ```
      sudo yum groupinstall 'Development Tools'
      sudo yum install pkgconfig
      sudo yum install clang*
      sudo yum install llvm*
      ```

### Build Instructions
```
git clone https://github.com/kflowd/kflowd.git
cd kflowd
git submodule update --init --recursive
cd src
make
make rpm deb
```

### Installation Instructions
Packages can be installed on Linux x86_64 and arm64 based platforms:
```
sudo yum install ./kflowd-x.x.x.<amd64 | aarch64>.rpm
sudo apt install ./kflowd-x.x.x_<x86_64 | arm64>.deb
```
Note that build artifacts for all versions on x86_64 platform can be downloaded under GitHub actions:
[Pre-built binaries and rpm/deb packages](https://github.com/kflowd/kflowd/actions/workflows/kflowd-ci.yml)

<br>

### License
This work is licensed under [GNU General Public License v2.0](https://github.com/kflowd/kflowd/blob/master/LICENSE).
```
SPDX-License-Identifier: GPL-2.0
```

### Acknowledgements
- **libbpf+CO-RE:** Andrii Nakryiko's Blog, **[BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)**
- **eBPF Tracing:** Brendan Gregg, **[Linux Extended BPF (eBPF) Tracing Tools](https://www.brendangregg.com/ebpf.html)**
- **SHA256:**       Cgminer (Bitcoin mining project), **[Fast SHA256 Implementation](https://github.com/fcicq/cgminer/)**
- **MD5:**          RSA Data Security, **[MD5 Message-Digest Algorithm](https://github.com/Zunawe/md5-c/)**

<br>
<div align="right">
<a href="https://github.com/kflowd/kflowd/graphs/traffic" target="_blank"><img src="https://img.shields.io/endpoint?url=https://kflowd.github.io/kflowd/gh-stats-clones.json"/></a>
<a href="https://github.com/kflowd/kflowd/graphs/traffic" target="_blank"><img src="https://img.shields.io/endpoint?url=https://kflowd.github.io/kflowd/gh-stats-clones-14d.json"/></a>
<br>
<a href="https://github.com/kflowd/kflowd/graphs/traffic" target="_blank"><img src="https://img.shields.io/endpoint?url=https://kflowd.github.io/kflowd/gh-stats-views.json"/></a>
<a href="https://github.com/kflowd/kflowd/graphs/traffic" target="_blank"><img src="https://img.shields.io/endpoint?url=https://kflowd.github.io/kflowd/gh-stats-views-14d.json"/></a>
</div>
