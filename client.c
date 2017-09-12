#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 12345

int main(){
	
	int clientSocket;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	char message[4] = "Test";

	//Creation of the socket (see server code)
	clientSocket = socket(PF_INET, SOCK_STREAM, 0);

	//Parameters of the server
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	//Connect to the server
	addr_size = sizeof(serverAddr);
	connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

	//Received message
	recv(clientSocket, buffer, 1024, 0);

	//message is printed
	printf("Data received: %s",buffer); 

	//Send a message
	if(sendto(clientSocket, message, sizeof(message), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
		perror("ERROR message not send");

	return 0;
}
