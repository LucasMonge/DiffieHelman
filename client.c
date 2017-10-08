#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <unistd.h>
#include <gmp.h>

#define PORT 12345
#define  MESSAGELEN  200
#define DHSIZE 256
#define  CIPHERTEXT_LEN ( MESSAGELEN )

//Generate a cryptosecure random number 
void randomGen(char* temp,int size){
	
	int i;
	char *t=malloc(8);
	for(i = 0;i<size;i++){	
		randombytes_buf(t,8);
		temp[i]=*t;
	}
	free(t);
}

//Convert a number in binary
char* convertBin(char *buf){

	char *temp=malloc(DHSIZE);
	int i;
	for(i = 0;i<DHSIZE;i++){
		if(buf[i]&1){
			temp[i]='1';
		}
		else{
			temp[i]='0';
		}
	}
	free(temp);
	return temp;
}

void copy(unsigned char* dest,unsigned char* src){

	int i;
	for(i=0;i<sizeof(src);i++){
		dest[i]=*src;
		src+=1;
	}
}
//Diffie Helmann Key generator
void exchangeKey(int* socket,struct sockaddr_in serverAddr,socklen_t addr_size, char* key){
	
	char buffer[MESSAGELEN];
	char g[DHSIZE];
	char  a[DHSIZE];
	char  p[DHSIZE]="23";
	
	//Generate random number
	randomGen(g,256);
	randomGen(a,256);
	//randomGen(p,256);
	
	//Initialization of the gmp variables
	mpz_t tempP,tempG,tempA, A, B, Key;
	mpz_init(tempP);
	mpz_init(tempG);
	mpz_init(tempA);
	mpz_init(A);
	mpz_init(B);
	mpz_init(Key);
	
	
	//Advert the server that exchange start
	if(sendto(*socket,"ExchangeKey",sizeof("ExchangeKey"),0,(struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	//Wait the server before send p
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");
	
	//Send g
	if(sendto(*socket, convertBin(g), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	//Wait the server before continue
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");

	//Convert the number in gmp format
	mpz_set_str(tempP,convertBin(p),2);
	mpz_set_str(tempG,convertBin(g),2);
	mpz_set_str(tempA,convertBin(a),2);
	
	mpz_nextprime(tempP,tempP);
	//Send p
	if(sendto(*socket, mpz_get_str(NULL,2,tempP), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	//Wait the server before continue
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");
	
	//Make A=g^a%p
	mpz_powm(A,tempG,tempA,tempP);
	
	//Send A to the server
	if(sendto(*socket, mpz_get_str(NULL, 2, A), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	
	//Receive B from the server
	if(recv(*socket, buffer, 1024, 0) >= 0){
		mpz_set_str(B,buffer,2);
		memset(buffer,0,DHSIZE);
	}
	
	//Key = B^a%p
	mpz_powm(Key, B, tempA, tempP);
	
	//Return the key
	mpz_get_str(key, 10, Key);
}
int main(){
	printf("\e[1;1H\e[2J");
	unsigned char key [DHSIZE];
	
	unsigned char nonce [crypto_secretbox_NONCEBYTES];
	unsigned char ciphertext[CIPHERTEXT_LEN];
	int clientSocket, choice = 0;
	unsigned char buffer[1024];
	//char keyCheck[5];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	unsigned char message[MESSAGELEN];
	unsigned char mac[crypto_secretbox_MACBYTES];
		
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
	printf("Server says: %s\n",buffer); 

	//Key exchange
	printf("Key exchange ...\n\n");
	exchangeKey(&clientSocket,serverAddr,addr_size, (char*)key);
	printf("The Key is: %s\n",key);

	
	while(1){

		printf("\n\nChoices:\n 1: Send a message\n 2: End communication\n");
		scanf("%d", &choice);
		switch(choice){

			case 1:
				getchar();
				printf("\nWrite your message :\n->");
				fgets((char*)&message,MESSAGELEN,stdin);

				//Generate a random nonce
				randomGen((char*)nonce,crypto_secretbox_NONCEBYTES);

				//Send a message
				crypto_secretbox_detached(ciphertext,mac, message,CIPHERTEXT_LEN, nonce, key);


				//Alert the server
				if(sendto(clientSocket, "transmit", 8, 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				recv(clientSocket, buffer, MESSAGELEN, 0);
				
				//Send the nonce
				if(sendto(clientSocket, nonce, crypto_secretbox_NONCEBYTES, 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				recv(clientSocket, buffer, MESSAGELEN, 0);
				//Send the mac
				if(sendto(clientSocket, mac, sizeof(mac), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				recv(clientSocket, buffer, MESSAGELEN, 0);
				//Send the cipher text
				if(sendto(clientSocket,ciphertext, sizeof(ciphertext), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				else
					printf("\nMessage sent\n\n");
				
				recv(clientSocket, buffer, MESSAGELEN, 0);
				memset(ciphertext,0,CIPHERTEXT_LEN);
				memset(buffer,0,MESSAGELEN);
				memset(message,0,MESSAGELEN);
				memset(nonce,0,crypto_secretbox_NONCEBYTES + 5);
				send(clientSocket,"Start",5,0);
				memset(mac, 0, crypto_secretbox_MACBYTES + 3);
				
				recv(clientSocket, nonce, crypto_secretbox_NONCEBYTES, 0);
				
				send(clientSocket,"Nonce",5,0);
				
				recv(clientSocket,mac,crypto_secretbox_MACBYTES,0);
				
				send(clientSocket,"MAC",3,0);
								
				recv(clientSocket, ciphertext, CIPHERTEXT_LEN, 0);
				
				if(crypto_secretbox_open_detached(message, ciphertext, mac, sizeof(ciphertext), nonce, key)>=0)
					printf("The server send me this : \n%s", message);
				else
					printf("Error decrypt\n");
				break;
			case 2:
				//Send a message to warn the server
				if(sendto(clientSocket, "Exit", sizeof("Exit"), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				//Close the socket
				close(clientSocket);
				return 0;
				break;
			default: 
				printf("Wrong choice, try again\n");
				getchar();
		}
	}
		
	return 0;
}
