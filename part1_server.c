#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include "cJSON.h"
#include <signal.h>

// The TCP port number is globally defined to receive the confuration parameters from client
#define TCP_PORT 8787
#define MAX_BUFFER_SIZE 63000
#define THRESHOLD 100


// The configuration parameters are stored in this struct
typedef struct {

	char server_ip[16];
	int udp_src_port;
	int udp_dest_port;
	int tcp_head_syn_port;
	int tcp_tail_syn_port;
	int tcp_port;
	int udp_payload_size;
	int inter_measurement_time;
	int udp_packet_train_size;
	int udp_packet_ttl;
} Config;


// Allows succesfull exit and to be used following closing the ports
void cleanExit() {exit(0);}

// Signal handler for SIGALRM to exit the program in case if RST is not received
// @param signum: The signal number
void handler(int signum) {
	printf("Insufficent data to compute the loss rate. Exiting...\n");
	exit(1);
}

// Function to parse the configuration parameters from config string received from client
// @param size: The size of the configuration string
// @param conf_str: The configuration string
Config *parse_config(long size, char *conf_str) {

	// Parsing the string read from the configuration string to json object
	cJSON *parser = cJSON_Parse(conf_str);
	if (!parser) {
		printf("Could not parse to JSON:%s\n", cJSON_GetErrorPtr());
		free(conf_str);
		return NULL;
	}

	cJSON *server_ip = cJSON_GetObjectItem(parser,"server_ip");
	cJSON *udp_src_port = cJSON_GetObjectItem(parser,"udp_src_port");
	cJSON *udp_dest_port = cJSON_GetObjectItem(parser,"udp_dest_port");
	cJSON *tcp_head_syn_port = cJSON_GetObjectItem(parser,"tcp_head_syn_port");
	cJSON *tcp_tail_syn_port = cJSON_GetObjectItem(parser,"tcp_tail_syn_port");
	cJSON *tcp_port = cJSON_GetObjectItem(parser,"tcp_port");
	cJSON *udp_payload_size = cJSON_GetObjectItem(parser,"udp_payload_size");
	cJSON *inter_measurement_time = cJSON_GetObjectItem(parser,"inter_measurement_time");
	cJSON *udp_packet_train_size = cJSON_GetObjectItem(parser,"udp_packet_train_size");
	cJSON *udp_packet_ttl = cJSON_GetObjectItem(parser,"udp_packet_ttl");

	// Store the params in the Config struct
	Config *conf = malloc(sizeof(Config));
	if (!conf) {
		printf("Failed to allocate memory for Config struct\n");
		cJSON_Delete(parser);
		free(conf_str);
		return NULL;
	}
	strcpy(conf->server_ip, cJSON_GetStringValue(server_ip));
	conf -> udp_src_port = cJSON_GetNumberValue(udp_src_port);
	conf -> udp_dest_port = cJSON_GetNumberValue(udp_dest_port);  
	conf -> tcp_head_syn_port = cJSON_GetNumberValue(tcp_head_syn_port);
	conf -> tcp_tail_syn_port = cJSON_GetNumberValue(tcp_tail_syn_port);
	conf -> tcp_port = cJSON_GetNumberValue(tcp_port);
	conf -> udp_payload_size = cJSON_GetNumberValue(udp_payload_size);
	conf -> inter_measurement_time = cJSON_GetNumberValue(inter_measurement_time);  
	conf -> udp_packet_train_size = cJSON_GetNumberValue(udp_packet_train_size); 
	conf -> udp_packet_ttl = cJSON_GetNumberValue(udp_packet_ttl);

	// Delete the parser and free the memory
	cJSON_Delete(parser);

	return conf;
}

/*
 * Function to open up a TCP connection to send the configuration parameters to client,
 * then receive UDP packets, calculates the delay between low and high entropy packets
 * listens for the TCP connection form the client and responds with the compression outcome
 */

int main() {

	struct itimerval timer;
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);

	// Set the timer for 100 seconds, if the TCP connection from client is not established within 100 seconds, exit
	timer.it_value.tv_sec = 100;
	timer.it_value.tv_usec = 0;

	// Set the interval to 0 (non-repeating timer)
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;

	// Start the timer
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
		perror("setitimer");
		exit(1);
	}

	// Set the signal handler for SIGALRM
	signal(SIGALRM, handler);


	// Create socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}


	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR , &opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	// Set the address and port
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( TCP_PORT );

	// Bind socket to the address and port
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
	{
		perror("bind failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// Listen for incoming connections
	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// Accept incoming connection
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}

	if (new_socket < 0) {
		perror("accept failed");
		exit(EXIT_FAILURE);
	}

	// Receive the config data from client
	char config_buffer[MAX_BUFFER_SIZE];
	int total_bytes_received = 0;
	int bytes_received = 0;
	do {
		bytes_received = recv(new_socket, config_buffer + total_bytes_received, MAX_BUFFER_SIZE - total_bytes_received, 0);
		if (bytes_received < 0) {
			perror( "Error receiving data from socket\n");
			return 1;
		}
		total_bytes_received += bytes_received;
	} while (bytes_received > 0 && total_bytes_received < MAX_BUFFER_SIZE);


	close(new_socket);
	close(server_fd);

	sleep(5);

	// Parse the config data and store in a Config struct
	Config *config_json = parse_config(total_bytes_received, config_buffer);
	if (config_json == NULL) {
		return -1;
	} 

	// Fill the config struct with the values from the config file
	int inter_meas_time = config_json->inter_measurement_time;
	int udp_packet_ttl = config_json->udp_packet_ttl;
	char *server_ip = config_json->server_ip;
	int udp_src_port = config_json->udp_src_port;
	int UDP_PORT = config_json->udp_dest_port;
	int tcp_port = config_json->tcp_port;
	int udp_payload_size = config_json->udp_payload_size;
	int train_size = config_json->udp_packet_train_size;

	int PACKET_SIZE = udp_payload_size + 28; // 20 bytes IP header + 8 bytes UDP header
	int MAX_PACKETS = train_size / PACKET_SIZE;


	int udp_socket,tcp_socket, bytes_sent,bytes_recv, i, j, num_packets;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len;
	char recv_buffer[PACKET_SIZE];
	char send_buffer[PACKET_SIZE];
	struct timeval tv;
	struct timeval t1, t2, t_start ,t_end;
	double arrival_time_l[MAX_PACKETS], arrival_time_h[MAX_PACKETS], diff_time;
	time_t start_time_l, end_time_l, start_time_h, end_time_h;
	double time_diff1, time_diff2;

	// Create UDP socket
	if ((udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	// Set server address and port
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(UDP_PORT);

	// Bind UDP socket to server address and port
	if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	// Set timeout for UDP socket
	tv.tv_sec = 10; // timeout after 1 second
	tv.tv_usec = 0;
	if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		perror("setsockopt failed");
		exit(EXIT_FAILURE);
	}

	while (1) {
		// Receive low entropy UDP packets from client
		num_packets = 0;
		while (num_packets < train_size) {
			client_addr_len = sizeof(client_addr);
			bytes_recv = recvfrom(udp_socket, recv_buffer, PACKET_SIZE, 0,
					(struct sockaddr *)&client_addr, &client_addr_len);
			if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				} else {
					perror("Error receiving packet");
					exit(1);
				}        
			}
			gettimeofday(&t2, NULL);
			if (num_packets == 0) {
				t_start = t2;
			}
			t_end = t2;
			num_packets++;
		}

		// Calculate the time difference for the first packet train
		time_diff1 = (t_end.tv_sec - t_start.tv_sec) * 1000.0;      // seconds to milliseconds
		time_diff1 += (t_end.tv_usec - t_start.tv_usec) / 1000.0;   // microseconds to milliseconds


		// Wait for some time before sending next packet train
		sleep(inter_meas_time);

		// Receive high entropy packets from client
		num_packets = 0;
		while (num_packets < train_size) {
			client_addr_len = sizeof(client_addr);
			bytes_recv = recvfrom(udp_socket, recv_buffer, PACKET_SIZE, 0,
					(struct sockaddr *)&client_addr, &client_addr_len);
			if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				} else {
					perror("Error receiving packet");
					exit(1);
				}
			}
			gettimeofday(&t2, NULL);
			if (num_packets == 0) {
				t_start = t2;
			}
			t_end = t2;
			num_packets++;
		}

		// Calculate the time difference for the second packet train
		time_diff2 = (t_end.tv_sec - t_start.tv_sec) * 1000.0;      // seconds to milliseconds
		time_diff2 += (t_end.tv_usec - t_start.tv_usec) / 1000.0;   // microseconds to milliseconds

		// Close the UDP socket
		close(udp_socket);

		// prepare the message to be sent to the client
		if (abs(time_diff2 - time_diff1) > THRESHOLD) {
			printf("%s\n", "Compression detected!" );
			strcpy(send_buffer, "Compression detected!");
		} else {
			printf("%s\n", "No compression was detected.");
			strcpy(send_buffer, "No compression was detected.");
		}

		// Set the variables for the TCP connection to listen the client and send the calculations back
		int server_output, new_socket, valread;
		struct sockaddr_in adr_out;
		int opt = 1;
		int addrlen = sizeof(adr_out);
		char buffer[1024] = {0};

		// Create socket file descriptor
		if ((server_output = socket(AF_INET, SOCK_STREAM, 0)) == 0)
		{
			perror("socket failed");
			exit(EXIT_FAILURE);
		}

		// Attach socket to the port 
		if (setsockopt(server_output, SOL_SOCKET, SO_REUSEADDR , &opt, sizeof(opt)))
		{
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}
		adr_out.sin_family = AF_INET;
		adr_out.sin_addr.s_addr = INADDR_ANY;
		adr_out.sin_port = htons( TCP_PORT );

		// Bind socket to the address and port
		if (bind(server_output, (struct sockaddr *)&adr_out,
					sizeof(adr_out))<0)
		{
			perror("bind failed");
			exit(EXIT_FAILURE);
		}

		// Listen for incoming connections
		if (listen(server_output, 3) < 0)
		{
			perror("listen");
			exit(EXIT_FAILURE);
		}

		// Accept incoming connection
		if ((new_socket = accept(server_output, (struct sockaddr *)&adr_out,
						(socklen_t*)&adr_out))<0)
		{
			perror("accept");
			exit(EXIT_FAILURE);
		}

		// Receive message from client
		valread = read(new_socket, buffer, 1024);
		if (valread < 0) {
			perror("Error receiving packet");
			exit(1);
		}

		// Send message to client
		if(send(new_socket, send_buffer, strlen(send_buffer), 0) < 0) {
			perror("send failed");
			exit(EXIT_FAILURE);
		}


		// Close the TCP socket and exit
		close(new_socket);
		close(server_output);
		signal(SIGTERM, cleanExit);
		signal(SIGINT, cleanExit);

		return 0;
	}
}