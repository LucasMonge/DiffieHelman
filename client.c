#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int main(){
  int clientSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;
  int port = 12345;
  char message[4] = "Test";

  clientSocket = socket(PF_INET, SOCK_STREAM, 0);
  
  serverAddr.sin_family = AF_INET;
  
  serverAddr.sin_port = htons(port);
  
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  


  addr_size = sizeof(serverAddr);
  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

  //Receved message
  recv(clientSocket, buffer, 1024, 0);

	//message is printed
  printf("Data received: %s",buffer); 
  
  sendto(clientSocket, message, sizeof(message), 0, (struct sockaddr *)&serverAddr, addr_size);
    

  return 0;
}
