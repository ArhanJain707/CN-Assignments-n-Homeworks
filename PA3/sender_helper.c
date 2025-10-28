
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "sender.h"
#include "config.h"

unsigned long long seq = 0;

struct Packet{
	unsigned char* pkt;
	unsigned long long seq_no;
	size_t len;
	struct Packet *next;
	bool isack;
};

struct Packet *sent_queue = NULL;
int q_len = 0;

// send buffer, buf, of length len
void rdt_send(const void *buf, size_t len)
{
	struct Packet *p = malloc(sizeof(struct Packet));;
	p->pkt = buf;
	p->seq_no = seq;
	p->len = len;
	make_pkt(p->pkt,p->len);
	udt_send(p->pkt,p->len);
	seq+=(p->len-PACKET_HEADER_LEN);
	int first = 0;
	if(queue empty){ // NEED TO MAKE THIS FUNCTION
		first = 1;
	}
	enqueue(p,sent_queue);  // NEED TO MAKE THIS FUNCTION
	if(first==1){
		start_timer();
	}
	
}

// received an acknowledgment number, ackno
void rdt_recv_ack(unsigned long long ackno)
{
	struct Packet *p = head;
	while(p->seq_no < ackno){
		p->isack = true;
		p = p->next;
		dequeue(sent_queue);
		if(p==NULL){
			break;
		}
	}
	stop_timer();
	if(queue not empty){
		start_timer();
	}
}

// timeout event handler
void timeout()
{
	if(queue.isempty()==false){
		udt_send(/*packet at head of queue*/);
		start_timer();
	}
}
