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
	//Wait the server before continue
	if(recv(*socket, buffer, 1024, 0)<0)
		perror("ERROR");

	//Convert the number in gmp format
	mpz_set_str(tempP,convertBin(p),2);
	//gmp_printf("P is : %Zd\n",tempP);
	mpz_set_str(tempG,convertBin(g),2);
	//gmp_printf("G is : %Zd\n",tempG);
	mpz_set_str(tempA,convertBin(a),2);
	//gmp_printf("a is : %Zd\n",tempA);
	
	//Make A=g^a%p
	mpz_powm(A,tempG,tempA,tempP);
	//gmp_printf("A is : %Zd\n",A);

	//Send A to the server
	if(sendto(*socket, mpz_get_str(NULL, 2, A), DHSIZE ,0 , (struct sockaddr *) &serverAddr,addr_size)<0){
		perror("ERROR");
	}
	
	//Receive B from the server
	if(recv(*socket, buffer, 1024, 0) >= 0){
		//printf("Received B\n");
		mpz_set_str(B,buffer,2);
		//gmp_printf("B is: %Zd\n", B);
		memset(buffer,0,DHSIZE);
	}
	
	//Key = B^a%p
	mpz_powm(Key, B, tempA, tempP);
	//gmp_printf("The Key is: %Zd\n",Key);
	
	//Return the key
	mpz_get_str(key, 10, Key);
}
int main(){
	
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
	printf("Data received: %s",buffer); 

	//Key exchange
	//while(1){
		exchangeKey(&clientSocket,serverAddr,addr_size, (char*)key);
		printf("The Key is: %s\n",key);
	//	recv(clientSocket, keyCheck, 1024, 0);
	//	if(strcmp((char*)key,"0")&&strcmp(keyCheck,"OK")){
	//		break;
	//	}
	//}
	
	while(1){

		printf("\nChoices:\n 1: Send message\n 2: End communication\n 3: Exchange keys\n");
		scanf("%d", &choice);
		switch(choice){

			case 1:
				getchar();
				printf("Write your message :\n");
				fgets((char*)&message,MESSAGELEN,stdin);

				//Generate a random nonce
				randomGen((char*)nonce,crypto_secretbox_NONCEBYTES);
				printf("key before is:%s\n",key);

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
					printf("Message sent\n");
				
				
				//printf("key is:%s\n",key);
				recv(clientSocket, buffer, MESSAGELEN, 0);
				memset(ciphertext,0,CIPHERTEXT_LEN);
				memset(buffer,0,MESSAGELEN);
				memset(message,0,MESSAGELEN);
				memset(nonce,0,crypto_secretbox_NONCEBYTES+5);
				send(clientSocket,"Start",5,0);
				
				recv(clientSocket, nonce, crypto_secretbox_NONCEBYTES, 0);
				
				memset(buffer,0,MESSAGELEN);
				send(clientSocket,"Nonce",5,0);
				
				recv(clientSocket,mac,128,0);
				send(clientSocket,"MAC",3,0);
				recv(clientSocket, buffer, MESSAGELEN, 0);
				printf("Nonce is : %s\n",nonce);
				
				if(crypto_secretbox_open_detached(message, buffer,mac, sizeof(buffer), nonce, key)>=0)
					printf("%s", message);
				else
					printf("Error decrypt\n");
				printf("key after decrypt is:%s\n",key);
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
				//Key exchange
				printf("The Key is: %s\n",key);
				break;
			default: 
				printf("Wrong choice, try again\n");
				getchar();
		}
	}
		
	return 0;
}
