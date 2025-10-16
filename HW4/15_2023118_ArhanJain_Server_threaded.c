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

pthread_mutex_t stdinLock = PTHREAD_MUTEX_INITIALIZER;

void event_loop(int new_s, int client_num)
{
	fd_set readfds;
	struct timeval tv;
	int max_fd = STDIN_FILENO;
	int activity;
	char buf[MAX_LINE];

	if (new_s > max_fd) {
		max_fd = new_s;
	}

	while(1) {
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(new_s, &readfds);

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

		if (FD_ISSET(new_s, &readfds)) {
			// data is available at client[i] connection
			int bytes = recv(new_s, buf, sizeof(buf), 0);
			buf[MAX_LINE-1] = '\0';
			if (bytes <= 0) {
				printf("client %i disconnected.\n", client_num);
				close(new_s);
				return;
			}
			printf("Client %i says: %s\n", client_num, buf);
			fflush(stdout);
		}

		if  (FD_ISSET(STDIN_FILENO, &readfds)) {
			// data is avaliable at stdin
			if (pthread_mutex_trylock(&stdinLock) == 0 && fgets(buf, sizeof(buf), stdin) != NULL) {
				buf[MAX_LINE-1] = '\0';

				// broadcast message to all clients
				if (send(new_s, buf, strlen(buf)+1, 0) < 0) {
					perror("send error");
					close(new_s);
					return;
				}
				pthread_mutex_unlock(&stdinLock);
			}
		}
	}
	close(new_s);
}


typedef struct {
	int num;
	int client_s;
} client_thread_args;

void client_handler(void *arguments){
	client_thread_args *argu = (client_thread_args *)arguments;
	event_loop(argu->client_s, argu->num);
	free(argu);
	pthread_exit(NULL);}

int main() {
	struct sockaddr_in sin;
	int s;
	int client_num = 0;
	pthread_t clients[20];

	/* build address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(SERVER_PORT);

	/* setup passive open */
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(1);}

	if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		perror("bind failed");
		exit(1);}

	if (listen(s, MAX_PENDING) < 0) {
		perror("listen failed");
		exit(1);}

	while(1) {
		int new_s;
		socklen_t addr_len;
		if ((new_s = accept(s, (struct sockaddr *)&sin, &addr_len)) < 0) {
			perror("accept failed");
			exit(1);}
		printf("Client %d connected.\n", client_num+1);
		
		client_thread_args *args = malloc(sizeof(client_thread_args));
		args->num = client_num+1;
		args->client_s = new_s;

		pthread_create(&clients[client_num++], NULL, (void *)client_handler, (void *)args);
	}

	close(s);
	return 0;
}
