#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h> // IP 주소 조작 

struct ethheader{
  u_char ether_dhost[6]; // 목적지 호스트 주소 
  u_char ether_shost[6]; // 출발지 호스트 주소 
  u_short ether_type; // 프로토콜 타입 
};

struct ipheader{
  unsigned char iph_ihl:4; // IP 헤더 길이 
  unsigned char iph_ver:4; // IP 버전 
  unsigned char iph_tos; // 서비스 유형 
  unsigned short int iph_len; // IP 패킷 길이 
  unsigned short int iph_ident; // 식별자 
  unsigned short int iph_flag:3; // 단편화 플래그 
  unsigned short int iph_offset:13; // 플래그 오프셋 
  unsigned char iph_ttl; // 타임 투 리브 
  unsigned char iph_protocol; // 프로토콜 타입 
  unsigned short int iph_chksum; // IP 데이터그램 체크섬 
  struct in_addr iph_sourceip; // 출발지 IP 주소 
  struct in_addr iph_destip; // 목적지 IP 주소 
};

struct tcpheader{
    u_short tcp_sport; // 출발지 포트 
    u_short tcp_dport; // 목적지 포트 
    u_int tcp_seq; // 순차 번호 
    u_int tcp_ack; // 확인 번호 
    u_char tcp_offx2; // 데이터 오프셋 
    u_char tcp_flags; // 플래그 
    u_short tcp_win; // 윈도우 
    u_short tcp_sum; // 체크섬 
    u_short tcp_urp; // 긴급 데이터 확인 포인터 
    #define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
};

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if(ntohs(eth->ether_type) == 0x0800){ // IP 패킷인지 확인 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이를 바이트로 계산

        if(ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜만 분리! 
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4; // TCP 헤더 길이를 바이트로 계산
			
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

  // TCP만 캡처 
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  } // 에러 감지 

  // 패킷 캡처 시작 
  pcap_loop(handle, -1, got_packet, NULL);
  
  pcap_close(handle);
  return 0;
}
