#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 12345

int main(){

	int welcomeSocket, newSocket;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	
	//Creation of the socket AF_INET: protocol IPv4//SOCK_STREAM: type of the socket//0: TCP protocol
	welcomeSocket = socket(AF_INET, SOCK_STREAM, 0); 

	//Define the parameters of the server
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	//Link the socket and the server
	bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
	
	//Listen for connexion (max=5)
	if(listen(welcomeSocket,5)==0)
		printf("Listening\n");
	else
		printf("Error\n");

	//Accept the client connexion to the socket
	addr_size = sizeof(serverStorage);
	newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);
	
	//Send a message to the client
	strcpy(buffer,"Hello World\n");
	if(send(newSocket,buffer,13,0)<0)
		perror("ERROR bad message\n");
	else
		memset(&buffer[0], 0, sizeof(buffer)); //Erase the buffer
	
	while(1){
		
		//Receive a message from the client
		if(recv(newSocket, buffer, 1024, 0) < 0)
			perror("ERROR in reception");
		else
			printf("message is: %s\n", buffer);
		
	}
	
	return 0;
	}
