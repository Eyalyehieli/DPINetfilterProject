#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "myStruct.h"


int main()
{
    puts("client");
    int sockfd;
    struct sockaddr_in  servaddr;
    int sizeServAddr=sizeof(servaddr);
    //yStruct structToSend={0,0.5,1};
    myStruct structToSend={"123456789"};
    char buffer[1024];
    int n;

    if((sockfd=socket(PF_INET,SOCK_DGRAM,0))<0)
    {
       puts("creation socket failed");
    }
    puts("socket succedded");

    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    //while(1)
    //{
    if(n=sendto(sockfd,(char*)&structToSend,sizeof(structToSend),0,(struct sockaddr*)&servaddr,sizeServAddr)<0)
    {
      perror("send to error");
    }
    printf("send pkt\n");
   //}
    //recvfrom(sockfd,(char*)buffer,sizeof(buffer),0,(struct sockaddr*)&servaddr,&sizeServAddr);

    //printf("%s",buffer);
    close(sockfd);

    return 0;
}
