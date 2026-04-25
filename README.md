# Firewall By C

Updated by Shishir

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
