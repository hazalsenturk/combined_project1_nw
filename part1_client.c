#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "cJSON.h"
#include <signal.h>
#include <errno.h>

/* Use the TCP port number 8787 as client TCP port number */
#define BUFFER_SIZE 65536
#define SERVER_TCP_PORT 8787

/*
 * IMPORTANT: File directory for the high entropy data,
 * the filename should be changed to the name of the file containing the high entropy data
 */
#define HIGH_ENTROPY_FILENAME "highEntropyData"

/* 
 * A function to exit the program cleanly
 */
void cleanExit() {exit(0);}

/* 
 * The high entropy data is read from a file previously generated on Mac to provide a high entropy source
 * Function reads the randomH file and returns the data as a char array
 * Takes the filename and the size of bytes to read as input
 * @param filename: the name of the file containing the high entropy data
 * @param size: the size of the data to read in bytes
 */

char* read_high_entropy_data(const char* filename, int size) {
	FILE* fp = fopen(filename, "rb");
	if (!fp) {
		perror("Error opening file");
		return NULL;
	}
	char* data = (char*) malloc(size);
	if (!data) {
		perror("Error allocating memory");
		fclose(fp);
		return NULL;
	}
	size_t bytes_read = fread(data, 1, size, fp);
	if (bytes_read != size) {
		perror("Error reading file");
		free(data);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	return data;
}

/*
 * The main function for the client's actions
 * Initates a TCP connection with the server
 * Sends the configuration file to the server
 * Sends the low entropy data to the server with UDP packets
 * waits for the inter_measurement_time given in the configuration file
 * Sends the high entropy data to the server with UDP packets
 * Opens a TCP connection with the server to receive the calculations from the server regarding the compression
 * Prints the results to the console
 * @param argc: the number of command line arguments that should contain the configuration file
 */
int main(int argc, char *argv[]) {

	// Program expects the config file as command line argument
	if (argc < 2) {
		printf("Usage: ./program <filename>\n");
		return -1;
	}

	// Read the configuration file
	char *config_filename = argv[1];
	FILE *conf_file = fopen(argv[1], "r");
	if (conf_file == NULL) {
		perror("Error opening config file");
		return -1;
	}

	fseek(conf_file, 0, SEEK_END);
	long conf_file_size = ftell(conf_file);
	fseek(conf_file, 0, SEEK_SET);
	char *config_data = (char *) malloc(conf_file_size + 1);
	fread(config_data, conf_file_size, 1, conf_file);
	fclose(conf_file);
	config_data[conf_file_size] = '\0';

	// Parse the configuration data using cJSON library to JSON object
	cJSON *config_json = cJSON_Parse(config_data);
	if (config_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			fprintf(stderr, "Error parsing JSON: %s\n", error_ptr);
		}
		return -1;
	}

	// Read the configuration values from the parsed JSON object and store them in variables
	int udp_payload_size = cJSON_GetObjectItem(config_json, "udp_payload_size")->valueint;
	int udp_packet_train_size = cJSON_GetObjectItem(config_json, "udp_packet_train_size")->valueint;
	int inter_measurement_time = cJSON_GetObjectItem(config_json, "inter_measurement_time")->valueint;
	int udp_packet_ttl = cJSON_GetObjectItem(config_json, "udp_packet_ttl")->valueint;
	char *server_ip = cJSON_GetObjectItem(config_json, "server_ip")->valuestring;
	int udp_src_port = cJSON_GetObjectItem(config_json, "udp_src_port")->valueint;
	int udp_dest_port = cJSON_GetObjectItem(config_json, "udp_dest_port")->valueint;

	if (server_ip == NULL || udp_src_port == 0 || udp_dest_port == 0 || udp_payload_size == 0 || inter_measurement_time == 0 || udp_packet_train_size == 0) {
		printf("Error: Incomplete config values\n");
		cJSON_Delete(config_json); // delete the JSON object
		free(config_data); // free the string memory
		return 1;
	}

	int sockfd, optval=1;
	struct sockaddr_in server_addr;

	// Create a socket for TCP connection
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &optval,sizeof (optval)) < 0)
	{
		perror ("couldn’t reuse address");
		abort ();
	}


	// Set up the server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_TCP_PORT);
	if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
		perror("inet_pton");
		exit(EXIT_FAILURE);
	}

	// Connect to the server
	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	// Open the configuration file for reading, configuration file should be named as config
	FILE *config_file = fopen(config_filename, "r");
	if (config_file == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	// Read the contents of the configuration file into a buffer
	char bufferconf[1024];
	size_t bytes_read;
	while ((bytes_read = fread(bufferconf, 1, sizeof(bufferconf), config_file)) > 0) {
		if (send(sockfd, bufferconf, bytes_read, 0) == -1) {
			perror("send");
			exit(EXIT_FAILURE);
		}
	}

	// Close the configuration file
	fclose(config_file);

	// Close the socket
	close(sockfd);

	// Sleep before sending the data for the connection to be closed and open a new connection
	sleep(5);

	// Set up the server address
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(server_ip);
	server_address.sin_port = htons(udp_dest_port);
	int sock, i, sent_bytes;
	char buffer[BUFFER_SIZE];
	struct iphdr *ip_header;
	struct udphdr *udp_header;


	// Create the socket for UDP packets
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket() failed");
		return -1;
	}

	// Enable the don't fragment bit
	int value = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value)) < 0) {
		perror("setsockopt() failed");
		return -1;
	}

	// Declare a variable for PACKET_ID
	uint16_t packet_id = 0;

	// Send n UDP packets with low entropy data
	for (i = 0; i < udp_packet_train_size; i++) {
		memset(buffer, 0, sizeof(buffer));
		ip_header = (struct iphdr *) buffer;
		udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr));
		ip_header->saddr = INADDR_ANY;
		ip_header->daddr = inet_addr(server_ip);

		udp_header->source = htons(udp_src_port);
		udp_header->dest = htons(udp_dest_port);
		udp_header->uh_dport = htons(udp_dest_port);
		udp_header->uh_sport = htons(udp_src_port);
		udp_header->uh_ulen = htons(udp_payload_size + sizeof(struct udphdr));

		// Set PACKET_ID in the UDP header, Copy PACKET_ID into the first 16 bits of the payload
		uint16_t *payload_packet_id = (uint16_t *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
		*payload_packet_id = htons(packet_id);
		char low_entropy_data[1024];

		int j;
		for (j = 0; j < udp_payload_size; j++) {
			low_entropy_data[j] = 0;
		}
		if (!low_entropy_data) {
			return -1;
		}
		strncpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), low_entropy_data, udp_payload_size);
		sent_bytes = sendto(sock, buffer, udp_payload_size, 0, (struct sockaddr *) &server_address, sizeof(server_address));
		if (sent_bytes < 0) {
			perror("sendto() failed");
			return -1;
		}


		// Increment PACKET_ID for the next packet
		packet_id++;

		// Clear the payload buffer and send the packet
		memset(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), 0, udp_payload_size);
		if (sendto(sock, buffer, udp_payload_size, 0, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
			perror("sendto failed");
			exit(EXIT_FAILURE);
		}
	}

	// Wait Inter-Measurement Time (γ) seconds
	sleep(inter_measurement_time);

	// Declare a variable for PACKET_ID for the high entropy data
	uint16_t packet_id_high = 0;

	char* high_entropy_data = read_high_entropy_data(HIGH_ENTROPY_FILENAME, udp_payload_size);
	if (!high_entropy_data) {
		perror("Error reading high entropy data from file\n");
		return -1;
	}

	// Send n UDP packets with high entropy data
	for (i = 0; i < udp_packet_train_size; i++) {

		// Clear the buffer and set the IP and UDP headers
		memset(buffer, 0, sizeof(buffer));
		ip_header = (struct iphdr *) buffer;
		udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr));
		ip_header->saddr = INADDR_ANY;
		ip_header->daddr = server_address.sin_addr.s_addr;
		udp_header->source = htons(udp_src_port);
		udp_header->dest = htons(udp_dest_port);
		udp_header->uh_dport = htons(udp_dest_port);
		udp_header->uh_sport = htons(udp_src_port);
		udp_header->uh_ulen = htons(udp_payload_size + sizeof(struct udphdr));

		// Set PACKET_ID in the UDP header, Copy PACKET_ID into the first 16 bits of the payload
		uint16_t *payload_packet_id = (uint16_t *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
		*payload_packet_id = htons(packet_id_high);

		// Copy the high entropy data into the payload
		strncpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), high_entropy_data, udp_payload_size);

		// Send the packet
		sent_bytes = sendto(sock, buffer, udp_payload_size, 0, (struct sockaddr *) &server_address, sizeof(server_address));
		if (sent_bytes < 0) {
			perror("sendto() failed");
			free(high_entropy_data);
			return -1;
		}

		// Increment PACKET_ID for the next packet
		packet_id_high++;

		// Clear the payload buffer and send the packet
		memset(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), 0, udp_payload_size);
		if (sendto(sock, buffer, udp_payload_size, 0, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
			perror("sendto failed");
			exit(EXIT_FAILURE);
		}
	}


	free(high_entropy_data);

	// Close the socket
	close(sock);

	// Wait for 15 seconds for the TCP connection to be established to get the data from the server
	sleep(15);

	char buffer1[1024] = {0};
	char *hello = "Hello from client";
	int sock_tcp = 0, valread;
	if ((sock_tcp = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("\n Socket creation error \n");
		return -1;
	}

	// Set the server address
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(SERVER_TCP_PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, server_ip , &server_address.sin_addr)<=0)
	{
		perror("\nInvalid address/ Address not supported \n");
		return -1;
	}

	// Connect to the server
	if (connect(sock_tcp, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		perror("\nCould not retrieve data.Connection Failed. Exiting. \n");
		close(sock_tcp);
		return -1;
	}

	// Send message to server
	if(send(sock_tcp, hello, strlen(hello), 0) < 0)
	{
		perror("Could not send message to server. Exiting. \n");
		close(sock_tcp);
		return -1;
	}

	// Receive calculations from server and print them to the console
	valread = read(sock_tcp, buffer1, 1024);
	if (valread < 0)
	{
		perror("Could not receive data from server. Exiting. \n");
		close(sock_tcp);
		return -1;
	}
	
	printf("%s\n", buffer1);

	// Close the socket and exit
	close(sock_tcp);
	signal(SIGTERM, cleanExit);
	signal(SIGINT, cleanExit);

	return 0;
}
