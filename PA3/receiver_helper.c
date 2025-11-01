
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "receiver.h"
#include "config.h"

unsigned long long seq = 0;

struct Packet{
	unsigned char* pkt;
	unsigned long long seq_no;
	size_t len;
	struct Packet *next;
	bool isack;
};

unsigned char* buffer;
unsigned long long buffer_size = 0;

struct Packet *received_queue = NULL;

int notiflag = 0;
// received a packet, pkt
// len, length of the paket
void rdt_recv(const unsigned char *pkt, size_t len)
{
	unsigned long long seq_num = get_seqno(pkt);
	if(seq_num<seq){
		send_ack(seq);
		return;
	}
	if(seq==seq_num){
		//struct Packet *p = malloc(sizeof(struct Packet));
		unsigned char *data = get_data(pkt);
		
		//insert data into buffer
		//update buffer size
		notiflag = 1;
		seq+=(len-PACKET_HEADER_LEN);
	}
	while(seq == /*SEQUENCE NUMBER OF PACKET AT HEAD OF RECEIVED QUEUE*/){
		unsigned char *buff = get_data(head->pkt);
		//insert this into buffer
		//update buffer size

		seq+=(head->len - PACKET_HEADER_LEN);
		dequeue();
		notiflag = 1;
	}
	if(seq_num>seq){
		struct Packet *p = malloc(sizeof(struct Packet));
		p->pkt = pkt;
		p->seq_no = seq_num;
		p->len = len;
		enqueue(p);
	}
	send_ack(seq);
	if(notiflag==1){
		notify_app();
	}
}

// app requested a data of length len
// buf is len bytes long
// returns the number of bytes copied to buf
size_t app_recv(unsigned char *buf, size_t len)
{
	if(buffer_size==0){
		return 0;
	}
	if(len<buffer_size){
		memcpy(buf, buffer, len);
		buffer_size-=len;
		//update buffer by removing first len bytes
		return len;
	}else{
		memcpy(buf,buffer,buffer_size);
		int k = buffer_size;
		buffer_size = 0;
		//make buffer 0 or empty or smthn
		return k;
	}
	return 0;
}
