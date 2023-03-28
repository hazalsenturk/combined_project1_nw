# Compression Detection README
## Author
Gizem Hazal Senturk

## Overview

Compression Detection is a program that detects compression in network traffic. It consists of two parts: Part 1 and Part 2. The program uses the provided configuration file to set up and run both parts. The files submitted contains the following files:

- `part1_server.c`
- `part1_client.c`
- `part2_client.c`
- `cJSON.c`
- `cJSON.h`
- `highEntropyData`
- sample config file `config`
- standalone.pcapng
- client-server.pcapng
- README.txt

## Requirements

The configuration file <b>must</b> be in JSON format and include the following keys:

```json

{
  "server_ip": "SERVER_IP (DEST_IP)",
  "udp_src_port": "UDP_SRC_PORT",
  "udp_dest_port": "UDP_DEST_PORT",
  "tcp_head_syn_port": "TCP_HEAD_SYN_PORT",
  "tcp_tail_syn_port": "TCP_TAIL_SYN_PORT",
  "tcp_port": "TCP_PORT",
  "udp_payload_size": 1000, // default
  "inter_measurement_time": 15, // default
  "udp_packet_train_size": 6000, // default
  "udp_packet_ttl": 255 // default
}
```
## Instructions

### Part 1
1. Fill the configuraiton file above for the missing values. Place the part1_server.c and cJSON.c files on the server side and part1_client.c, config and cJSON.c files on the client side.

2. Compile the server and client files on the machines:
<br>gcc part1_server.c cJSON.c
<br>gcc part1_client.c cJSON.c 

3. Start the server side by running 
<br>./a.out

4. Start the client side with the configuration file in the same directory:
<br>./a.out "config_filename"

<br>The compression output will be printed on both server and client sides.

### Part2 
1. Change the server_ip in the configuration file to the target machine's IP. As tcp_head_syn_port and tcp_tail_syn_port are used for the RST packets, they should be closed ports on the target machine. Can use big numbers eg. 34876.

2. Ensure that the target machine is turned on before starting the client side.

3. Compile the client file:
<br>gcc part2_client.c cJSON.c 

4. Run the client side with the configuration file in the same directory. Since this uses raw sockets use sudo to run the program:
<br>sudo ./a.out config

The output will display the time difference for the RST packets and whether compression is detected or not. If there's a timeout, an error message will be printed, and the program will exit.

