/* 
Copyright (c) 2009, Pascal Mainini
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
 * The name Pascal Mainini may not be used to endorse or promote
   products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

#define VERSION "2.0"
#define NUM_VLANS 4096
#define PRINTHELP() printf("Usage: vlandump [-h] [-v] [-o] [-c] "\
                           "[-r file] [-i iface]\n")


///////////////////////////// types

typedef uint64_t count_t;

typedef struct {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
} header_ethernet_t;
#define ET_VLAN 0x0081
#define SIZE_ETHERNET sizeof(header_ethernet_t)

typedef struct {
    count_t count;
    count_t id;
} vlan_entry_t;


///////////////////////////// global vars

char verbose = 0;
char sort_by_count = 0;
char reverse_order = 0;
pcap_t *handle;

count_t vlans[NUM_VLANS][2];
count_t total_count = 0;
count_t tagged_count = 0;
count_t untagged_count = 0;


///////////////////////////// functions

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{   
    total_count++;

    if(header->len < SIZE_ETHERNET) {
        return;
    }

    const header_ethernet_t *ethernet = (header_ethernet_t*)(p);

    if(ethernet->type == ET_VLAN) {
        tagged_count++;
        int vlan = ((*(p+SIZE_ETHERNET)&017)<<8) + *(p+SIZE_ETHERNET+1);
        vlans[vlan][0]++;
        vlans[vlan][1] = vlan;

        if(verbose) {
            printf("Got packet, VLAN: %d\n", vlan);
        }
    } else {   
        untagged_count++;
        if(verbose) {
           printf("Got untagged packet!\n");
        }
    }
}

static int compare_counts(const void *c1, const void *c2)
{
    const vlan_entry_t *e1 = (vlan_entry_t*) c1;
    const vlan_entry_t *e2 = (vlan_entry_t*) c2;

    if(reverse_order) {
        return (e1->count - e2->count)*-1;
    } else {
        return e1->count - e2->count;
    }
}

void print_totals()
{
    printf("\n+---------------------------------------------+\n");

    int total_vlans = 0;
    if(tagged_count > 0) {
        int i,j;
        if(sort_by_count) {
            qsort(vlans, NUM_VLANS, sizeof(count_t)*2, compare_counts);
            for(i = 0; i < NUM_VLANS; i++) {
                if(vlans[i][0] > 0) {
                    total_vlans++;
                    printf("| VLAN %5lld: %20lld pkts.      |\n",
                             vlans[i][1], vlans[i][0]);
                }
            }
        } else {
            for(i = 0; i < NUM_VLANS; i++) {
                if(reverse_order) {
                    j = NUM_VLANS-i;
                } else {
                    j = i;
                }
                
                if(vlans[j][0] > 0) {
                    total_vlans++;
                    printf("| VLAN %5lld: %20lld pkts.      |\n",
                             vlans[j][1], vlans[j][0]);
                }
            } 
        }
    } else {
        printf("| No tagged packets received!                 |\n");
    }

    printf("+---------------------------------------------+\n");
    printf("| Total VLANs:           %20d |\n", total_vlans);
    printf("| Total pkts:            %20lld |\n", total_count);
    printf("| Total tagged pkts:     %20lld |\n", tagged_count);
    printf("| Total untagged pkts:   %20lld |\n", untagged_count);
    printf("+---------------------------------------------+\n");
}

void interrupted(int sig) 
{
    pcap_breakloop(handle);
}


///////////////////////////// main

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int c;
    char mode = 'u';
    const char *source = NULL;

    printf("vlandump %s - dump 802.1q VLANs using pcap.\n", VERSION);
    printf("Copyright (c) 2009, Pascal Mainini\n");
    printf("All rights reserved.\n\n");

    while ((c = getopt (argc, argv, "hvocr:i:")) != -1) {
        switch (c) {
            case 'h':
                PRINTHELP();
                exit(EXIT_SUCCESS);
            case 'v':
                verbose = 1;
                break;
            case 'o':
                reverse_order = 1;
                break;
            case 'c':
                sort_by_count = 1;
                break;
            case 'r':
            case 'i':
                if(mode != 'u') {
                    fprintf(stderr, "-i and -r can't be used together!\n");
                    abort();
                }
                mode = c;
                source = optarg;
                break;
           case '?':
                if (optopt == 'i') {
                    fprintf (stderr, 
                            "An interface must be specified with -i.\n");
                } else if (optopt == 'r') {
                    fprintf (stderr, 
                            "A pcap-file must be specified with -r.\n");
                } else {
                    PRINTHELP();
                    abort();
                }
            default:
                abort();
        }
    }

    if(mode == 'r') {
        handle = pcap_open_offline(source, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening file %s: %s\n", source, errbuf);
            abort();
        }
    } else if(mode == 'i') {
        handle = pcap_open_live(source, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", source, errbuf);
            abort();
        }
    } else {
        PRINTHELP();
        exit(EXIT_SUCCESS);
    }

    if(pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Unsuported link-type!\n");
        pcap_close(handle);
        abort();
    }

    if(pcap_setnonblock(handle, 1, errbuf) != 0) {
        fprintf(stderr, "Couldn't put handle in non-blocking mode: %s\n", 
            errbuf);
        pcap_close(handle);
        abort();
    }

    if (signal (SIGINT, interrupted) == SIG_IGN) {
        signal (SIGINT, SIG_IGN);
    }
    if (signal (SIGHUP, interrupted) == SIG_IGN) {
        signal (SIGHUP, SIG_IGN);
    }
    if (signal (SIGTERM, interrupted) == SIG_IGN) {
        signal (SIGTERM, SIG_IGN);
    }

    memset(&vlans, 0, NUM_VLANS*sizeof(count_t)*2);

    char up = 1;
    int result;
    while(up) {
        if((result = pcap_dispatch(handle, -1, got_packet, NULL)) > 0) {
            usleep(100);
        } else if(result == 0 && mode == 'i') {
            usleep(100);
        } else {
            up = 0;
        }
    }

    if(result == -1) {
        fprintf(stderr, "Error occured: %s\n", errbuf);
    } else if(result == -2) {
        printf("\nAborted.\n");
    }

    pcap_close(handle);
    print_totals();

    exit(EXIT_SUCCESS);
}

