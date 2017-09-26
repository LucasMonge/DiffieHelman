#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sodium.h>
#include <gmp.h>

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

//Convert into binary number
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

//Generate a cryptosecure random number
void randomGen(char* temp){
	
	int i;
	char *t=malloc(8);
	for(i = 0;i<256;i++){
		
		randombytes_buf(t,8);
		temp[i]=*t;
	}
	free(t);
}

//Diffie Helmann Key generator
void exchangeKey(int* socket,struct sockaddr_in serverAddr,socklen_t addr_size, char* key){
	char p[DHSIZE];
	char g[DHSIZE];
	char buffer[DHSIZE];
	char b[DHSIZE];
	
	randomGen(b);
	printf("First step in exchange\n");
	//Initialization of the gmp variables
	mpz_t tempP,tempG,tempB, A, B, Key;
	mpz_init(tempP);
	mpz_init(tempG);
	mpz_init(tempB);
	mpz_init(B);
	mpz_init(A);	
	mpz_init(Key);	
	//Pass to the next step
	if(send(*socket,"First step",13,0)<0)
		perror("ERROR");
		
	//Get p
	if(recv(*socket, buffer, 1024, 0) >= 0){
		printf("Received p\n");
		strcpy(p, buffer);
		memset(buffer,0,DHSIZE);
		//Pass to the next step
		if(send(*socket,"P received",13,0)<0)
			printf("ERROR");
	}
	//Get g
	if(recv(*socket, buffer, 1024, 0) >= 0){
		printf("Received g\n");
		strcpy(g, buffer);
		memset(buffer,0,DHSIZE);
		//Pass to the next step
		if(send(*socket,"G received",13,0)<0)
			perror("ERROR");	
	}
	
	//Convert p,g and b in gmp type
	mpz_set_str(tempP,convertBin(p),2);
	//gmp_printf("P is : %Zd\n",tempP);
	mpz_set_str(tempG,convertBin(g),2);
	//gmp_printf("G is : %Zd\n",tempG);
	mpz_set_str(tempB,convertBin(b),2);
	//gmp_printf("b is : %Zd\n",tempB);
	
	//Make B=g^b%p
	mpz_powm(B,tempG,tempB,tempP);
	//gmp_printf("B is : %Zd\n",B);
	
	//Receive A
	if(recv(*socket, buffer, 1024, 0) >= 0){
		//printf("Received A\n");
		mpz_set_str(A,buffer,2);
		//gmp_printf("A is: %Zd\n", A);
		memset(buffer,0,DHSIZE);
		//Send B
		if(send(*socket, mpz_get_str(NULL, 2, B), DHSIZE ,0 )<0){
			perror("ERROR");
		} 
		
	}
	
	//Key = A^b%p
	mpz_powm(Key, A, tempB, tempP);
	
	//Return the key
	mpz_get_str(key, 10, Key);
	
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
	unsigned char key [crypto_secretbox_KEYBYTES];
	unsigned char nonce [crypto_secretbox_NONCEBYTES];
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

	//Listen to a client connection
	listenSocket(&welcomeSocket,&newSocket,serverAddr,serverStorage,addr_size);
	
	while(1){
		
		//Receive a message from the client
		if(recv(newSocket, buffer, 1024, 0) >= 0){
			
			//Exchange the key
			if(!strcmp((char *)buffer,"ExchangeKey")){
				printf("Exchange\n");
				exchangeKey(&newSocket,serverAddr,addr_size, (char*)key);
				printf("The Key is: %s\n",key);
			}
			//Decrypt the message
			else if (!strcmp((char *)buffer,"transmit")){
				send(newSocket,"Start",5,0);
				recv(newSocket, nonce, 1024, 0);
				memset(buffer,0,1024);
				send(newSocket,"Nonce",5,0);
				recv(newSocket, buffer, 1024, 0);
				if(crypto_secretbox_open_easy(message, buffer, sizeof(buffer), nonce, key)>=0)
					printf("Message is: %s\n", message);
				else
					printf("Error decrypt\n");
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
		memset(buffer, 0, 1024);
	}
	
	return 0;
	}
