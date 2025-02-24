# Firewall By C 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_RULES 100
#define MAX_IP_LENGTH 16
#define MAX_PROTOCOL_LENGTH 8

typedef struct {
    char blockedIP[MAX_IP_LENGTH];
    int blockedPort;
    char blockedProtocol[MAX_PROTOCOL_LENGTH];
} FirewallRule;

FirewallRule rules[MAX_RULES];
int ruleCount = 0;
pcap_t *handle = NULL; // Handle for pcap session

// Function to display welcome message
void displayWelcomeMessage() {
    printf("\n");
    printf("\t****************************************************\n");
    printf("\t*                                                  *\n");
    printf("\t*                WELCOME TO YOUR                   *\n");
    printf("\t*          CUSTOM NETWORK FIREWALL SYSTEM          *\n");
    printf("\t*                                                  *\n");
    printf("\t****************************************************\n");
    printf("\t*                                                  *\n");
    printf("\t*          Secure, Filter, and Protect             *\n");
    printf("\t*       Your Network with Confidence Today!        *\n");
    printf("\t*                                                  *\n");
    printf("\t****************************************************\n");
    printf("\n");
}

// Signal handler for Ctrl+C
void handleInterrupt(int signal) {
    if (handle != NULL) {
        pcap_close(handle);
        handle = NULL;
    }
    printf("\nReturning to menu...\n");
    exit(0); // Exit the current process, which will reset the menu loop
}

// Function to add a rule
void addRule() {
    if (ruleCount >= MAX_RULES) {
        printf("Maximum number of rules reached!\n");
        return;
    }

    FirewallRule rule;
    printf("Enter blocked IP (or NONE to ignore): ");
    scanf("%15s", rule.blockedIP);

    printf("Enter blocked port (or 0 to ignore): ");
    scanf("%d", &rule.blockedPort);

    printf("Enter blocked protocol (TCP/UDP/ANY): ");
    scanf("%7s", rule.blockedProtocol);

    rules[ruleCount++] = rule;
    printf("Rule added successfully!\n");
}

// Function to display rules
void displayRules() {
    if (ruleCount == 0) {
        printf("No rules defined.\n");
        return;
    }

    printf("Firewall Rules:\n");
    for (int i = 0; i < ruleCount; i++) {
        printf("Rule %d: IP=%s, Port=%d, Protocol=%s\n",
               i + 1,
               rules[i].blockedIP,
               rules[i].blockedPort,
               rules[i].blockedProtocol);
    }
}

// Function to delete a rule
void deleteRule() {
    if (ruleCount == 0) {
        printf("No rules to delete.\n");
        return;
    }

    int ruleIndex;
    printf("Enter the rule number to delete (1 to %d): ", ruleCount);
    scanf("%d", &ruleIndex);

    if (ruleIndex < 1 || ruleIndex > ruleCount) {
        printf("Invalid rule number.\n");
        return;
    }

    // Shift remaining rules to delete the selected one
    for (int i = ruleIndex - 1; i < ruleCount - 1; i++) {
        rules[i] = rules[i + 1];
    }

    ruleCount--;
    printf("Rule %d deleted successfully!\n", ruleIndex);
}

// Function to check if a packet matches any rules
bool isBlocked(const char *srcIP, const char *dstIP, int port, const char *protocol) {
    for (int i = 0; i < ruleCount; i++) {
        FirewallRule rule = rules[i];

        if (strcmp(rule.blockedIP, "NONE") != 0 && strcmp(rule.blockedIP, dstIP) != 0) {
            continue;
        }
        if (rule.blockedPort != 0 && rule.blockedPort != port) {
            continue;
        }
        if (strcmp(rule.blockedProtocol, "ANY") != 0 && strcmp(rule.blockedProtocol, protocol) != 0) {
            continue;
        }

        return true;
    }
    return false;
}

// Function to process a packet
void processPacket(const u_char *packet, int length) {
    struct iphdr *ipHeader = (struct iphdr *)(packet + 14);
    struct sockaddr_in srcAddr, dstAddr;

    srcAddr.sin_addr.s_addr = ipHeader->saddr;
    dstAddr.sin_addr.s_addr = ipHeader->daddr;

    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(srcAddr.sin_addr), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dstAddr.sin_addr), dstIP, INET_ADDRSTRLEN);

    const char *protocol = (ipHeader->protocol == IPPROTO_TCP) ? "TCP" :
                           (ipHeader->protocol == IPPROTO_UDP) ? "UDP" : "OTHER";

    int port = 0;

    if (isBlocked(srcIP, dstIP, port, protocol)) {
        printf("Blocked: SRC=%s, DST=%s, PROTOCOL=%s, PORT=%d\n", srcIP, dstIP, protocol, port);
    } else {
        printf("Allowed: SRC=%s, DST=%s, PROTOCOL=%s, PORT=%d\n", srcIP, dstIP, protocol, port);
    }
}

// Function to capture live traffic
void captureTraffic() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevices, *device;
    struct pcap_pkthdr header;
    const u_char *packet;

    if (pcap_findalldevs(&allDevices, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    device = allDevices;
    if (!device) {
        fprintf(stderr, "No devices found.\n");
        return;
    }
    printf("Using device: %s\n", device->name);

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(allDevices);
        return;
    }

    pcap_freealldevs(allDevices);

    printf("Capturing traffic... Press Ctrl+C to return to menu.\n");
    signal(SIGINT, handleInterrupt);

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet) {
            processPacket(packet, header.len);
        }
    }

    pcap_close(handle);
    handle = NULL;
}

// Function to test a specific packet
void testPacket() {
    char testSrcIP[MAX_IP_LENGTH], testDstIP[MAX_IP_LENGTH];
    int testPort;
    char testProtocol[MAX_PROTOCOL_LENGTH];

    printf("Enter source IP address (e.g., 192.168.0.1): ");
    scanf("%15s", testSrcIP);

    printf("Enter destination IP address (e.g., 192.168.0.2): ");
    scanf("%15s", testDstIP);

    printf("Enter port number (e.g., 80 for HTTP): ");
    scanf("%d", &testPort);

    printf("Enter protocol (TCP/UDP): ");
    scanf("%7s", testProtocol);

    // Check if the packet is blocked
    if (isBlocked(testSrcIP, testDstIP, testPort, testProtocol)) {
        printf("Test Packet Blocked: SRC=%s, DST=%s, PROTOCOL=%s, PORT=%d\n", testSrcIP, testDstIP, testProtocol, testPort);
    } else {
        printf("Test Packet Allowed: SRC=%s, DST=%s, PROTOCOL=%s, PORT=%d\n", testSrcIP, testDstIP, testProtocol, testPort);
    }
}

// Main function
int main() {
    int choice;

    displayWelcomeMessage();

    while (1) {
        printf("\nMenu:\n");
        printf("1. Add Rule\n");
        printf("2. Display Rules\n");
        printf("3. Test Packets\n");
        printf("4. Capture Live Traffic\n");
        printf("5. Delete Rule\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                addRule();
                break;
            case 2:
                displayRules();
                break;
            case 3:
                testPacket(); // Test packet option now works
                break;
            case 4:
                captureTraffic();
                break;
            case 5:
                deleteRule(); // Delete rule functionality added
                break;
            case 6:
                printf("Exiting firewall...\n");
                return 0;
            default:
                printf("Invalid choice. Try again.\n");
        }
    }
}
