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
#define  MESSAGELEN  30
#define DHSIZE 256
#define  CIPHERTEXT_LEN ( crypto_secretbox_MACBYTES +MESSAGELEN )

void printHex(char *buf){
		int i;
	for(i = 0; i<256/8; i++){
		printf("%hhx", buf[i]);
	}
	printf("\n");
}

//Convert into binary number
void randomGen(char* temp){
	
	
	int i;
	char *t=malloc(8);
	//printf("Size : %d\n",strlen(buf));
	for(i = 0;i<256;i++){
		
		randombytes_buf(t,8);
		temp[i]=*t;
	}
	free(t);
}
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


//Diffie Helmann Key generator
void exchangeKey(int* socket,struct sockaddr_in serverAddr,socklen_t addr_size, char* key){
	
	char buffer[MESSAGELEN];
	char g[DHSIZE];
	//randombytes_buf(g, DHSIZE);
	char  a[DHSIZE];
	//randombytes_buf(p, DHSIZE);
	char  p[DHSIZE];
	//randombytes_buf(a, DHSIZE);
	

	randomGen(g);
	randomGen(a);
	randomGen(p);
	
	/*temp=convertBin(a);
	printf("Size : %d\n",strlen(temp));
	int i=0;
	for(i=0;i<256;i++){
		printf("%c",temp[i]);
	}
	printf("\n");*/
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
	//Send p
	if(sendto(*socket, convertBin(p), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	//Wait the server before send g
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");
	//Send g
	if(sendto(*socket, convertBin(g), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");

	//Convert the number in gmp format
	mpz_set_str(tempP,convertBin(p),2);
	gmp_printf("P is : %Zd\n",tempP);
	mpz_set_str(tempG,convertBin(g),2);
	gmp_printf("G is : %Zd\n",tempG);
	mpz_set_str(tempA,convertBin(a),2);
	gmp_printf("a is : %Zd\n",tempA);
	
	//Make A=g^a%p
	mpz_powm(A,tempG,tempA,tempP);
	gmp_printf("A is : %Zd\n",A);

	if(sendto(*socket, mpz_get_str(NULL, 2, A), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	} 
	//memset(buffer, 0, DHSIZE);
	if(recv(*socket, buffer, 1024, 0) >= 0){
		printf("Received B\n");
		mpz_set_str(B,buffer,2);
		gmp_printf("B is: %Zd\n", B);
		memset(buffer,0,DHSIZE);
	}
	mpz_powm(Key, B, tempA, tempP);
	gmp_printf("The Key is: %Zd\n",Key);
	
	
	mpz_get_str(key, 10, Key);
}
int main(){
	
	unsigned char key [crypto_secretbox_KEYBYTES];
	unsigned char nonce [crypto_secretbox_NONCEBYTES] = "1234";
	unsigned char ciphertext[CIPHERTEXT_LEN];
	int clientSocket, choice = 1;
	unsigned char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	unsigned char message[MESSAGELEN] = "Hello world";
		
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
	
		printf("\nChoices:\n 1: Send message\n 2: End communication\n 3: Exchange keys\n");
		scanf("%d", &choice);
		switch(choice){
			case 1:
				//Send a message
				crypto_secretbox_easy(ciphertext, message, sizeof(message), nonce, key);
				if(sendto(clientSocket, "transmit", 8, 0, (struct sockaddr *)&serverAddr, addr_size)>=0)
					perror("ERROR message not send");
				if(sendto(clientSocket, nonce, crypto_secretbox_NONCEBYTES, 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				if(sendto(clientSocket,ciphertext, sizeof(ciphertext), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				break;
			case 2:
				//Send a message to warn the server
				if(sendto(clientSocket, "Exit", sizeof("Exit"), 0, (struct sockaddr *)&serverAddr, addr_size)<0)
					perror("ERROR message not send");
				//Close the socket
				close(clientSocket);
				return 0;
				break;
			case 3:
				exchangeKey(&clientSocket,serverAddr,addr_size, (char*)key);
				printf("The Key is: %s\n",key);
				break;
			default: 
				printf("Wrong choice, try again\n");
		}
	}
		
	return 0;
}
