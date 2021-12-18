#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "myStruct.h"






int main()
{
    puts("server");
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    int sizeClieAddr=sizeof(cliaddr);
    myStruct *structToRecv= malloc(sizeof(myStruct));
    unsigned char buffer[]="successfuly sent";
    int n;

     if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
     {
        puts("creation socket failed");
     }
      puts("socket succedded");

     memset(&servaddr, 0, sizeof(servaddr));
     memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    if ( bind(sockfd, (const struct sockaddr *)&servaddr,sizeof(servaddr)) < 0 )
    {
        puts("bind failed");
    }
    puts("bind succedded");

    n=recvfrom(sockfd,(char*)structToRecv,sizeof(myStruct),0,(struct sokaddr*)&cliaddr,&sizeClieAddr);
    puts("incoming data seuccessful\n");
    printf("got %d bytes, expected to get %d bytes\n",n, sizeof(*structToRecv));
    //sendto(sockfd,(char*)buffer,sizeof(buffer),0,(struct sokaddr*)&cliaddr,sizeClieAddr);

    puts(structToRecv->str);
    close(sockfd);

    return 0;
}
