// Source: https://book.systemsapproach.org/foundation/software.html
// sudo lsof -i :5432

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#define SERVER_PORT  5432
#define MAX_PENDING  5
#define MAX_LINE     256

int clients[8];
int active_clients = 0;
int listening_socket = -1;


void event_loop(int new_s)
{
	fd_set readfds;
	struct timeval tv;
	int max_fd = STDIN_FILENO;
	int activity;
	char buf[MAX_LINE];
	struct sockaddr_in sin;
	socklen_t addr_len = sizeof(sin);

	if (listening_socket > max_fd) {
		max_fd = listening_socket;
	}

	while(1) {
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(listening_socket, &readfds);

		for(int i = 0; i < 8; i++){
			if(clients[i]>0){
				FD_SET(clients[i], &readfds);
			}
			if(clients[i] > max_fd){
				max_fd = clients[i];
			}
		}


		tv.tv_sec = 30;
		tv.tv_usec = 0;

		activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);

		if (activity < 0) {
			perror("select");
			break;
		} else if (activity == 0) {
			printf("No activity for 30 secs.\n");
			continue;
		}

		if (FD_ISSET(listening_socket, &readfds)) {
			if ((new_s = accept(listening_socket, (struct sockaddr *)&sin, &addr_len)) < 0) {
				perror("accept failed");
				exit(1);
			}
			for(int i = 0; i < 8; i++){
				if(clients[i]==0){
					clients[i] = new_s;
					active_clients++;
					printf("Connection established, soocket fd: %d\n",clients[i]);
					break;
				}
			}
			if(active_clients>=8){
				close(new_s);
			}
		}
		for(int i = 0; i < 8; i++){
			// data is available at client[i] connection
			if(clients[i]>0 && FD_ISSET(clients[i], &readfds)){
				int bytes = recv(clients[i], buf, sizeof(buf), 0);
				buf[MAX_LINE-1] = '\0';
				if (bytes <= 0) {
					printf("client disconnected.\n");
					close(clients[i]);
					clients[i] = 0;
					active_clients--;
				}else{

					printf("Client says: %s\n", buf);
				}
			}
		}

		if  (FD_ISSET(STDIN_FILENO, &readfds)) {
			// data is avaliable at stdin
			if (fgets(buf, sizeof(buf), stdin) != NULL) {
				buf[MAX_LINE-1] = '\0';
				
				// broadcast message to all clients
				for(int i = 0; i < 8; i++){
					if(clients[i]!=0){
						if (send(clients[i], buf, strlen(buf)+1, 0) < 0) {
							perror("send error");
							close(clients[i]);
							return;
						}
						break;
					}
				}
			}
		}
	}
	for(int i = 0; i < 8; i++){
		close(clients[i]);
	}
}

int main()
{
	struct sockaddr_in sin;
	//socklen_t addr_len;
	int s, new_s;

	for(int i = 0; i < 8; i++){
		clients[i] = 0;
	}
	/* build address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(SERVER_PORT);

	/* setup passive open */
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(1);
	}
	if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		perror("bind failed");
		exit(1);
	}
	if (listen(s, MAX_PENDING) < 0) {
		perror("listen failed");
		exit(1);
	}

	/*if ((new_s = accept(s, (struct sockaddr *)&sin, &addr_len)) < 0) {
		perror("accept failed");
		exit(1);
	}*/
	new_s = s;
	listening_socket = s;
	event_loop(new_s);
	for(int i = 0; i < 8; i++){
		close(clients[i]);
	}

	close(s);
	close(listening_socket);
	return 0;
}
