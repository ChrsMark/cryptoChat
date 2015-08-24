/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	char buf[100];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;

	fd_set socks;        /* Socket file descriptors we want to wake
			up for, using select() */
	fd_set except_socks;
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		

		printf("Remote fd: %d, Local fd: %d\n",newsd , STDIN_FILENO );

		printf("\n\nNew Session Started!!!\n\n\n");

		/* We break out of the loop when the remote peer goes away */
		for (;;) {

			 //printf("ok in loop again\n");
			 FD_ZERO(&socks);
			 FD_SET(newsd,&socks);
			 FD_SET(STDIN_FILENO,&socks);
			 fprintf(stdout, "me: ");
			  fflush(stdout);
			 int readsocks = select(newsd+1, &socks, NULL, NULL, NULL);  //&except_socks

			 /* select() returns the number of sockets that had
				things going on with them -- i.e. they're readable. */
			
			/* Once select() returns, the original fd_set has been
				modified so it now reflects the state of why select()
				woke up. i.e. If file descriptor 4 was originally in
				the fd_set, and then it became readable, the fd_set
				contains file descriptor 4 in it. */
			//printf("readsocks = %d \n", readsocks);	
			if (readsocks < 0) {
				perror("select");
				exit(EXIT_FAILURE);
			} 
			else{
				/* handle remote input */
				if (FD_ISSET(newsd,&socks)){
					//printf("Checking remote buffer\n");
					n = read(newsd, buf, sizeof(buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from remote peer failed");
						else
							fprintf(stderr, "\nPeer went away...\n");
						break;
					}
					//toupper_buf(buf, n);
					fprintf(stdout, "\nRemote: ");
					fflush(stdout);
					if (insist_write(STDOUT_FILENO, buf, n) != n) {
						perror("write to local buff failed");
						break;
					}
					
				}
				else{ /* handle local-buffer */
					//printf("Checking local buffer\n");
					n = read(0, buf, sizeof(buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from localy  failed");
						else
							fprintf(stderr, "I went away\n");
						break;
					}
					//toupper_buf(buf, n);
					if (insist_write(newsd, buf, n) != n) {
						perror("write to remote failed");
						break;

					}
					//printf("ok i send the message to remote \n");
				}

			  
			}
			
		}
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}

