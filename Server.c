#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sodium.h>

#define PORT 12345
#define  MESSAGELEN  30
#define  CIPHERTEXT_LEN ( crypto_secretbox_MACBYTES +MESSAGELEN )
#define DHSIZE 256

void printHex(char *buf){
		int i;
	for(i = 0; i<256/8; i++){
		printf("%hhx", buf[i]);
	}
	printf("\n");
}

int exchangeKey(int* socket,struct sockaddr_in serverAddr,socklen_t addr_size){
	char p[DHSIZE];
	char g[DHSIZE];
	char buffer[DHSIZE];
	if(recv(*socket, buffer, 1024, 0) >= 0){
		strcpy(p, buffer);
		printHex(p);
	}
	if(recv(*socket, buffer, 1024, 0) >= 0){
		strcpy(g, buffer);
		printHex(g);
	}
	return 0;
}

//Listen and connect
int listenSocket(int* welcomeSocket,int* newSocket, struct sockaddr_in serverAddr,struct sockaddr_storage serverStorage,socklen_t addr_size){

	char recevedMessage[1024];
	//unsigned char buffer[CIPHERTEXT_LEN];

	//Listen for connexion (max=5)
	if(listen(*welcomeSocket,5)==0)
		printf("Listening\n");
	else
		printf("Error\n");
		
	//Accept the client connexion to the socket
	addr_size = sizeof(serverStorage);
	*newSocket = accept(*welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);
	
	//Send a message to the client
	strcpy(recevedMessage,"Hello World\n");
	if(send(*newSocket,recevedMessage,13,0)<0){
		perror("ERROR bad message\n");
		return -1;
	}
		
	return 0;
}


int main(){
	unsigned char message[MESSAGELEN];
	int welcomeSocket, newSocket;
	unsigned char key [crypto_secretbox_KEYBYTES]= "3";
	unsigned char nonce [crypto_secretbox_NONCEBYTES] = "1234";
	unsigned char buffer[CIPHERTEXT_LEN];
	struct sockaddr_in serverAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size=0;
	
	//Creation of the socket AF_INET: protocol IPv4//SOCK_STREAM: type of the socket//0: TCP protocol
	welcomeSocket = socket(AF_INET, SOCK_STREAM, 0); 

	//Define the parameters of the server
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	//Link the socket and the server
	bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
			
	listenSocket(&welcomeSocket,&newSocket,serverAddr,serverStorage,addr_size);
	
	while(1){
		
		//Receive a message from the client
		if(recv(newSocket, buffer, 1024, 0) >= 0){
			printf("Buffer is %d\n",strcmp((char *)buffer,"ExchangeKey"));
			
			if(!strcmp((char *)buffer,"ExchangeKey")){
				printf("Exchange\n");
				exchangeKey(&newSocket, serverAddr,addr_size);
			}
			//Decrypt the message
			else if (crypto_secretbox_open_easy(message, buffer, sizeof(buffer), nonce, key) >= 0){
				printf("Message is: %s\n", message);
			}
			//Test if the client closed the socket
			else if(!strcmp((char *)buffer,"Exit")){
				close(newSocket);
				printf("Socket closed\n");
				listenSocket(&welcomeSocket,&newSocket,serverAddr,serverStorage,addr_size);
			}
			else{
				printf("Ciphertext is: %s\n", buffer);
			}
		}
	}
	
	return 0;
	}
