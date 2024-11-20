# tseep - Network Traffic Capture Tool

**tseep** is a powerful network traffic capture tool designed to capture network packets and output them to various destinations. It supports saving captured traffic to local files, sending data over TCP to a remote server, or writing it directly to a TUN device for further analysis (e.g., to provide data to `Suricata`).

## Features

- **Capture Network Traffic**: Capture traffic from various network protocols.
- **Output to Local Files**: Save captured traffic in the `pcap` format for later analysis.
- **Support for TUN Devices**: Write captured traffic directly to a TUN device for use with tools like `Suricata` for intrusion detection/prevention system (IDS/IPS) analysis.
- **Send to Remote Server**: Stream captured packets over a TCP connection to a remote server.

## Installation

You can download precompiled binaries from the GitHub releases page or compile from source.

### Compiling from Source

To compile **tseep** from source, follow these steps:

1. Clone the repository:
```shell
git clone https://github.com/zxhio/tseep.git
cd tseep
```

2. Install dependencies and build:

```shell
go build -o tseep
```

3. After building, you can run **tseep** directly:

```shell
./tseep
```

## Usage

You can configure the tool's behavior with the following flags:

- `--iface` or `-i`: Specify the network interface to capture traffic from.
- `--file` or `-w`: Save captured packets to a local file.
- `--tcp`: Send captured packets to a remote server over TCP.
- `--tun`: Write captured packets to a TUN device.
- `--verbose`: Enable verbose logging for debugging.

The tool provides several flags to control how packets are captured and where the output is sent. Here are some examples of usage:

### Capture to local File

```shell
tseep dump -i <interface> --file capture.pcap
```

This command will capture network traffic and save it to a local file called `capture.pcap`.

### Send Captured Packets to a remote server via TCP

```shell
tseep dump -i <interface> --tcp <remote-server>:<port>
```

This command will capture traffic and send it over TCP to the specified remote server.

### Write Captured Packets to a TUN device

```shell
tseep dump -i <interface> --tun <TUN>
```

This command writes captured traffic directly to a TUN device, which can be used by tools like `Suricata`.

## TODO
1. **dump** command support more *tcpdump* options
    - host options *--host* *--dst-host* *--src-host*
    - port options *--port* *--dst-port* *--src-port*
    - tcp flags *--tcp-flags* which value is *syn* *psh* *ack* *fin* etc.
2. **serve** command support **dump** subcommand.