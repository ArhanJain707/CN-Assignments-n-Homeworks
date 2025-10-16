

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "server.h"


// server received a string message from client_id
// string message is in msg
// len is the length of the message
// num_clients is maximum number of clients
// valid_ids is an integer array of size num_clients
// all integers between 0 to num_clients-1 are potential clients
// a client X is valid if valid_ids[i] != -1

void recv_message(char *msg, int len, int client_id, int *valid_ids, int num_clients) {
// Hint: use sscanf to parse string (depending on your protocol)
// %n gives the offset of partially parsed string using sscanf
// use send_message API, see server.h
	printf("client %d: %s\n", client_id, msg);
	if (msg[0] == 'L' && msg[1] == 'I' && msg[2] == 'S' && msg[3] == 'T'){
		char servermsg[4096];
		strcpy(servermsg, "Available Clients : ");

		for (int i = 0; i < num_clients; i++){
			if (valid_ids[i] == 1){
				char id[12];
				sprintf(id, "%d", i);
				strcat(servermsg, id);
				strcat(servermsg, " ");}}
		send_message(servermsg, strlen(servermsg), client_id, SERVER_ID);}

	if (msg[0] == 'D' && msg[1] == 'A' && msg[2] == 'T' && msg[3] == 'A'){
		int i = 5, num_clients_data = 0, check = 0;

		while (check < len && msg[check] != ':'){
			check++;}
		if (check == len)
			return; // message doesn't have payload

		while (msg[i] != ' '){
			if (msg[i] == ' '){
				i++;
				continue;}
			num_clients_data = num_clients_data * 10 + (msg[i++] - '0');}
		i++;
		int send_messages_to[num_clients_data];
		int id = 0, j = 0;
		
		int client_count = 0;

		while (msg[i] != ':' && client_count < num_clients_data){
			if(msg[i] == ' '){
				send_messages_to[j++] = id;
				id = 0;
				client_count++;}
			else{
				id = id * 10 + (msg[i] - '0');}
			i++;}

		send_messages_to[j] = id; // for last id
		i += 2;
		int colon_index = -1;
		for (int k = 0; k < len; k++){
			if (msg[k] == ':'){
				colon_index = k;
				break;}}
		if (colon_index == -1 || colon_index + 2 >= len)
			return; // no payload to send
		colon_index += 2; // skip ": "
		char message_from_client[len];
		int k = 0;
		while (colon_index < len){
			message_from_client[k++] = msg[colon_index++];}
		message_from_client[k++] = '\0';

		for (int l = 0; l < client_count + 1; l++){
			if (send_messages_to[l] >= 0 && send_messages_to[l] < num_clients && valid_ids[send_messages_to[l]] != -1){
				send_message(message_from_client, k, send_messages_to[l], client_id);}}}
			}
