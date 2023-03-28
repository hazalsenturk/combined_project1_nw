#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <sys/select.h>
#include <signal.h>
#include "cJSON.h"
#include <pthread.h>

/*
 * A spoofed source IP address defined in the IP header, can be any IP address
 * THRESHOLD value is the time difference between the reset packets received for the low entropy data and high entropy data, default is 100
 * THRESHOLD vallue can be changed in demand
 */
#define SRC_IP "192.168.64.16"
#define BUFFER_SIZE 63000
#define THRESHOLD 100

/*
 * IMPORTANT: File directory for the high entropy data,
 * the filename should be changed to the name of the file containing the high entropy data
 */
#define HIGH_ENTROPY_FILENAME "highEntropyData"


#define NUM_RST_PACKETS 2  // Number of RST packets to receive
#define NUM_THREADS 2      // Number of thread used to receive RST packets. One for the low entropy data and
                            // one for the high entropy data
pthread_t thread1, thread2; // thread global variables


// Global variables to store the time differences
long high_rst_diffs_thread1_first[NUM_RST_PACKETS];
long high_rst_diffs_thread1_second[NUM_RST_PACKETS];
long high_rst_diffs_thread2_first[NUM_RST_PACKETS];
long high_rst_diffs_thread2_second[NUM_RST_PACKETS];

// Function prototypes
// @param sockfd: the socket file descriptor
unsigned short csum(unsigned short *ptr, int nbytes);
void send_syn_packet(int sockfd, struct sockaddr_in *target, int packet_ttl, int src_port) ;
long wait_for_rst_packet(int sockfd);
char* read_high_entropy_data(const char *filename, int size);
void* wait_for_rst_thread(void* arg);

/*
 * A function to handle the SIGALRM signal and exit the program if the timer expires
 * @param signum: the signal number
 */
void handler(int signum) {
	perror("Insufficent data to compute the loss rate. Exiting...\n");
	exit(EXIT_SUCCESS);
}

/* 
 * A function to exit the program cleanly, used to handle the SIGINT signal
 */
void cleanExit() {exit(0);}


/*
 * The main function
 * The program takes a single command line argument, the path to the config file
 * The configuration parameters will be read to a JSON object
 * Using raw sockets SYN packets are sent to the server and 
 * UDP packets are sent with UDP packets between SYN packets
 * This will be repeated or high and low entropy data
 * The time difference between the reset packets received for the low entropy data and high entropy data is calculated
 * Compression status is printed to the console
 * @param argc: the number of command line arguments, takes the config file path as the only argument
 */
int main(int argc, char *argv[]) {
	struct itimerval timer;

	// Set the timer for 60 seconds
	timer.it_value.tv_sec = 60;
	timer.it_value.tv_usec = 0;

	// Set the interval to 0 (non-repeating timer)
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;


	// Program expects the config file as command line argument

	if (argc != 2) {
		printf("Usage: %s <config_file>\n", argv[0]);
		return -1;
	}

	// Read the configuration file
	FILE *config_file = fopen(argv[1], "r"); // open the file in read mode

	if (config_file == NULL) {

		perror("Error: cannot open config file\n");
		return 1;
	}

	fseek(config_file, 0, SEEK_END); // move to the end of the file
	long file_size = ftell(config_file); // get the file size
	fseek(config_file, 0, SEEK_SET); // move back to the beginning of the file

	char* config_string = (char*) malloc(file_size + 1); // allocate memory for the string
	fread(config_string, 1, file_size, config_file); // read the file into the string
	fclose(config_file); // close the file
	config_string[file_size] = '\0'; // add a null terminator at the end of the string

	// Parse the configuration data using cJSON library to JSON object
	cJSON *json = cJSON_Parse(config_string); // parse the JSON string

	if (json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			printf("Error: %s\n", error_ptr);
		}
		return 1;
	}
	// Read the configuration values from the parsed JSON object and store them in variables
	char *server_ip = cJSON_GetObjectItem(json, "server_ip")->valuestring;
	int udp_src_port = cJSON_GetObjectItem(json, "udp_src_port")->valueint;
	int udp_dest_port = cJSON_GetObjectItem(json, "udp_dest_port")->valueint;
	int tcp_head_syn_port = cJSON_GetObjectItem(json, "tcp_head_syn_port")->valueint;
	int tcp_tail_syn_port = cJSON_GetObjectItem(json, "tcp_tail_syn_port")->valueint;
	int tcp_port = cJSON_GetObjectItem(json, "tcp_port")->valueint;
	int udp_payload_size = cJSON_GetObjectItem(json, "udp_payload_size")->valueint;
	int inter_measurement_time = cJSON_GetObjectItem(json, "inter_measurement_time")->valueint;
	int udp_packet_train_size = cJSON_GetObjectItem(json, "udp_packet_train_size")->valueint;
	int packet_ttl = cJSON_GetObjectItem(json, "udp_packet_ttl")->valueint;

	if (server_ip == NULL || udp_src_port == 0 || udp_dest_port == 0 || tcp_head_syn_port == 0 || tcp_tail_syn_port == 0 || tcp_port == 0 || udp_payload_size == 0 || inter_measurement_time == 0 || udp_packet_train_size == 0 || packet_ttl == 0) {
		perror("Error: Incomplete config values\n");
		cJSON_Delete(json); // delete the JSON object
		free(config_string); // free the string memory
		return 1;
	}

	fflush(stdout);


	int train_size, packet_id, loss_count;
	int i, j, ret;
	char buf[BUFFER_SIZE];


	char *target_ip = server_ip;
	// Set up the target ports for SYN and UDP packets
	int target_port_x = tcp_head_syn_port;
	int target_port_y = tcp_tail_syn_port;
	int target_port_udp = udp_dest_port;

	// Create a raw socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("socket");
		exit(1);
	}

	int one = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	// Set up the target addresses
	struct sockaddr_in target_x, target_y, target_udp;
	memset(&target_x, 0, sizeof(target_x));
	target_x.sin_family = AF_INET;
	target_x.sin_port = htons(target_port_x);
	inet_pton(AF_INET, target_ip, &target_x.sin_addr);

	memset(&target_y, 0, sizeof(target_y));
	target_y.sin_family = AF_INET;
	target_y.sin_port = htons(target_port_y);
	inet_pton(AF_INET, target_ip, &target_y.sin_addr);


	memset(&target_udp, 0, sizeof(target_udp));
	target_udp.sin_family = AF_INET;
	target_udp.sin_port = htons(target_port_udp);
	inet_pton(AF_INET, target_ip, &target_udp.sin_addr);

	// create the SOCK_DGRAM port for UDP packets
	int sock_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_udp < 0) {
		perror("socket");
		exit(1);
	}


	// Start the timer for the program that will run out if RST packets are lost
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
		perror("setitimer");
		exit(1);
	}

	// // Set the signal handler for SIGALRM
	signal(SIGALRM, handler);

    // Create the thread1 to wait for RST packets from the first 2 SYN packets
    if (pthread_create(&thread1, NULL, wait_for_rst_thread, &sockfd)!= 0) {
        perror("pthread_create");
        exit(1);
    }
	
    
    // Send the SYN packet to the port_x and timestamp it within the send_syn_packet function
	send_syn_packet(sockfd, &target_x, packet_ttl, tcp_port);

	train_size = udp_packet_train_size;
	packet_id = train_size - 1;
	loss_count = 0;
	// send the udp train with low entropy data
	for (i = 0; i < train_size; i++) {
		for (j = 0; j < udp_payload_size; j++) {
			buf[j] = 0;
		}
		((unsigned short *)buf)[0] = htons(packet_id--);
		ret = sendto(sock_udp, buf,udp_payload_size, 0, (struct sockaddr *)&target_udp, sizeof(target_udp));
		if (ret == -1) {
			perror("sendto");
		}
	}
	// Send the SYN packet to the port_y and timestamp it within the send_syn_packet function
	send_syn_packet(sockfd, &target_y, packet_ttl, tcp_port);
     
     // Wait for the thread1 to finish
    pthread_join(thread1, NULL);

	// sleep for inter_measurement_time
	sleep(inter_measurement_time);


	// prepare high entropy data

	char* high_entropy_data = read_high_entropy_data(HIGH_ENTROPY_FILENAME, udp_payload_size);
	if (!high_entropy_data) {
		free(high_entropy_data);
		return -1;
	}

    // Create the thread2 to wait for RST packets from the last 2 SYN packets
    if (pthread_create(&thread2, NULL, wait_for_rst_thread, &sockfd)!= 0) {
        perror("pthread_create");
        exit(1);
    }

	// Send the SYN packet to the port_x
	send_syn_packet(sockfd, &target_x , packet_ttl, tcp_port);

	// send high entropy data
	train_size = udp_packet_train_size;
	packet_id = train_size - 1;
	loss_count = 0;

	for (i = 0; i < train_size; i++) {

		strncpy(buf + sizeof(struct iphdr) + sizeof(struct udphdr), high_entropy_data, udp_payload_size);

		((unsigned short *)buf)[0] = htons(packet_id--);
		ret = sendto(sock_udp, buf, udp_payload_size, 0, (struct sockaddr *)&target_udp, sizeof(target_udp));
		if (ret == -1) {
			perror("Error sending UDP packet");
			free(high_entropy_data);
			return 1;}
	}

	// Send the second SYN packet to the port_y and timestamp it within the send_syn_packet function
	send_syn_packet(sockfd, &target_y, packet_ttl, tcp_port );

    // Wait for the thread2 to finish
    pthread_join(thread2, NULL);

    // Calculate the time differences and their difference between the two threads
    long diff_first = abs(high_rst_diffs_thread1_first[0] - high_rst_diffs_thread2_first[0]);
    long diff_second = abs(high_rst_diffs_thread1_second[0] - high_rst_diffs_thread2_second[0]);
    long diff_total = abs(diff_second - diff_first);

    // Print the results
    if (diff_total/1000 > THRESHOLD) {
    	printf("%s\n","Compression detected");
    }
    else {
    	printf("%s\n","No compression detected");
    }

    // Clean up the memory and close the sockets
	cJSON_Delete(json); // delete the JSON object
	free(config_string); // free the string memory
	free(high_entropy_data);
	close(sock_udp);
	close(sockfd);

	signal(SIGTERM, cleanExit);
	signal(SIGINT, cleanExit);

	return 0;
}

// Function to calculate the checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
	long sum;
	unsigned short oddbyte;
	short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

/*
 * Function to send a SYN packet to the target
 * Uses the raw socket and takes it as parameter
 * Also takes the target address and port as parameters
 * Also takes the packet TTL as a parameter
 * Prepares the headers for the IP and TCP packets
 * Computes the checksum for the IP header
 * Sends the packet
 * @param sockfd: the raw socket file descriptor
 * @param target: the target address and port
 * @param packet_ttl: the packet TTL
 * @param src_port: the source port
 */
void send_syn_packet(int sockfd, struct sockaddr_in *target, int packet_ttl, int src_port ) {
	// Prepare IP header
	struct iphdr iph;
	memset(&iph, 0, sizeof(iph));
	iph.ihl = 5;
	iph.version = 4;
	iph.tos = 0;
	iph.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph.id = htons(12345);
	iph.frag_off = 0;
	iph.ttl =packet_ttl; 
	iph.protocol = IPPROTO_TCP;
	iph.check = 0;
	iph.saddr = inet_addr(SRC_IP); // spoofed source IP address
	iph.daddr = target->sin_addr.s_addr;

	// Compute IP checksum
	iph.check = csum((unsigned short *)&iph, sizeof(struct iphdr));

	// Prepare TCP header
	struct tcphdr tcph;
	memset(&tcph, 0, sizeof(tcph));
	tcph.source = htons(src_port); // spoofed source port
	tcph.dest = target->sin_port;
	tcph.seq = random(); // random initial sequence number
	tcph.ack_seq = 0;
	tcph.doff = 5;
	tcph.fin = 0;
	tcph.syn = 1; // SYN packet
	tcph.rst = 0;
	tcph.psh = 0;
	tcph.ack = 0;
	tcph.urg = 0;
	tcph.window = htons(5840);
	tcph.check = 0;
	tcph.urg_ptr = 0;


	// Compute TCP checksum
	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t tcp_length;
		struct tcphdr tcp;
	} pseudo_header;

	pseudo_header.source_address = inet_addr(SRC_IP); // spoofed source IP address
	pseudo_header.dest_address = target->sin_addr.s_addr;
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(struct tcphdr));


	memcpy(&pseudo_header.tcp, &tcph, sizeof(struct tcphdr));

	tcph.check = csum((unsigned short *)&pseudo_header, sizeof(struct pseudo_header));

	// Send the SYN packet
	char packet[IP_MAXPACKET];
	memset(packet, 0, IP_MAXPACKET);
	memcpy(packet, &iph, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct iphdr), &tcph, sizeof(struct tcphdr));

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = target->sin_port;
	sin.sin_addr.s_addr = target->sin_addr.s_addr;

	if (sendto(sockfd, packet, iph.tot_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
		perror("sendto");
		exit(1);
	}

}

/*
 * Function to wait for the RST packets
 * Uses the raw socket and takes it as parameter
 * Waits for two RST packets
 * Returns the time difference between the two RST packets
 * @param sockfd: the raw socket file descriptor
 */
long wait_for_rst_packet(int sockfd) {

    // catch the RST packet and return the timestamp
	struct timeval end1;
    int count = 0;

    while (1) {
        char buffer[IP_MAXPACKET];
        memset(buffer, 0, IP_MAXPACKET);
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        int packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&source, &source_len);
        if (packet_len < 0) {
            perror("recvfrom");
            exit(1);
        }
        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct iphdr));
        if (tcp_header->rst == 1) {
            if (count == 0) {
                gettimeofday(&end1, NULL);
                printf("RST packet received at %ld microseconds.\n", end1.tv_usec);
                count++;
                return end1.tv_usec;
            }
        }
        
    }

    return 0;

}

	/*
	 * Function to read the high entropy data from the file
	 * Takes the filename and the size of the bytes to read as parameters
	 * Returns the data read from the file
	 * @param filename: the name of the file to read from
	 * @param size: the number of bytes to read
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


// Define the thread function to wait for RST packets
void* wait_for_rst_thread(void* arg) {
    int sockfd = *(int*)arg;
    long* rst_diff_ptr = (long*)malloc(sizeof(long));
    int num_rst_packets = 0;
    long* high_rst_diffs_first;
    long* high_rst_diffs_second;

    // Determine which global arrays to store the time differences in
    if (pthread_self() == thread1) {
        high_rst_diffs_first = high_rst_diffs_thread1_first;
        high_rst_diffs_second = high_rst_diffs_thread1_second;
    } else if (pthread_self() == thread2) {
        high_rst_diffs_first = high_rst_diffs_thread2_first;
        high_rst_diffs_second = high_rst_diffs_thread2_second;
    } else {
        // This should never happen
        perror("Error: invalid thread");
        exit(1);
    }

    while (num_rst_packets < NUM_RST_PACKETS) {
        // Wait for an RST packet
        *rst_diff_ptr = wait_for_rst_packet(sockfd);

        // Store the time difference in the appropriate global array
        if (num_rst_packets == 0) {
            high_rst_diffs_first[num_rst_packets] = *rst_diff_ptr;
        } else {
            high_rst_diffs_second[num_rst_packets - 1] = *rst_diff_ptr;
        }

        // Increment the counter
        num_rst_packets++;
    }

    free(rst_diff_ptr);
    pthread_exit(NULL);
}