#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h> // IP �ּ� ���� 

struct ethheader{
  u_char ether_dhost[6]; // ������ ȣ��Ʈ �ּ� 
  u_char ether_shost[6]; // ����� ȣ��Ʈ �ּ� 
  u_short ether_type; // �������� Ÿ�� 
};

struct ipheader{
  unsigned char iph_ihl:4; // IP ��� ���� 
  unsigned char iph_ver:4; // IP ���� 
  unsigned char iph_tos; // ���� ���� 
  unsigned short int iph_len; // IP ��Ŷ ���� 
  unsigned short int iph_ident; // �ĺ��� 
  unsigned short int iph_flag:3; // ����ȭ �÷��� 
  unsigned short int iph_offset:13; // �÷��� ������ 
  unsigned char iph_ttl; // Ÿ�� �� ���� 
  unsigned char iph_protocol; // �������� Ÿ�� 
  unsigned short int iph_chksum; // IP �����ͱ׷� üũ�� 
  struct in_addr iph_sourceip; // ����� IP �ּ� 
  struct in_addr iph_destip; // ������ IP �ּ� 
};

struct tcpheader{
    u_short tcp_sport; // ����� ��Ʈ 
    u_short tcp_dport; // ������ ��Ʈ 
    u_int tcp_seq; // ���� ��ȣ 
    u_int tcp_ack; // Ȯ�� ��ȣ 
    u_char tcp_offx2; // ������ ������ 
    u_char tcp_flags; // �÷��� 
    u_short tcp_win; // ������ 
    u_short tcp_sum; // üũ�� 
    u_short tcp_urp; // ��� ������ Ȯ�� ������ 
    #define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
};

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if(ntohs(eth->ether_type) == 0x0800){ // IP ��Ŷ���� Ȯ�� 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4; // IP ��� ���̸� ����Ʈ�� ���

        if(ip->iph_protocol == IPPROTO_TCP) { // TCP �������ݸ� �и�! 
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4; // TCP ��� ���̸� ����Ʈ�� ���
			
			printf("========== Print Start ==========\n"); 
			
            printf("[1] Ethernet Header\n");
            printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("[2] IP Header\n");
            printf("  Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("  Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("[3] TCP Header\n");
            printf("  Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Destination Port: %d\n", ntohs(tcp->tcp_dport));

            printf("========== Print End ==========\n\n"); 
        }
    }
}

int main(){
  pcap_t *handle;
  char buf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // TCP
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, buf);

  // TCP�� ĸó 
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  } // ���� ���� 

  // ��Ŷ ĸó ���� 
  pcap_loop(handle, -1, got_packet, NULL);
  
  pcap_close(handle);
  return 0;
}
