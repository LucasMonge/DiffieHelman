#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <unistd.h>

#define PORT 12345
#define  MESSAGELEN  4
#define  CIPHERTEXT_LEN ( crypto_secretbox_MACBYTES +MESSAGELEN )

int main(){
	unsigned char key [crypto_secretbox_KEYBYTES]= "3";
	unsigned char nonce [crypto_secretbox_NONCEBYTES] = "1234";
	unsigned char ciphertext[CIPHERTEXT_LEN];
	int clientSocket, choice = 1;
	unsigned char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	unsigned char message[4] = "Test";
	
	crypto_secretbox_easy(ciphertext, message, sizeof(message), nonce, key);
	printf("encrypted message is: %s\n", ciphertext);
	
	if (crypto_secretbox_open_easy(message, ciphertext, sizeof(ciphertext), nonce, key) >= 0)
		printf("Message is: %s\n", message);
	else
		printf("something is wrong");
		
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

	while(1){
	
		printf("Choices:\n 1: send message\n  2:end communication\n");
		scanf("%d", &choice);
		switch(choice){
			case 1:
				//Send a message
				//printf("Test");
				if(sendto(clientSocket, message, sizeof(message), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				break;
			case 2:
				if(sendto(clientSocket, "Exit", sizeof("Exit"), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				close(clientSocket);
				return 0;
				break;
			default: 
				printf("wrong choice, try again\n");
		}
	}
	//strcpy(message,"Exit");
	
		
	return 0;
}
