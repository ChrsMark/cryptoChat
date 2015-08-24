/*
 * socket-client.c
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

int main(int argc, char *argv[])
{
	int sd, port;
	ssize_t n;
	char buf[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	fd_set socks;        /* Socket file descriptors we want to wake
			up for, using select() */

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	//strncpy(buf, HELLO_THERE, sizeof(buf));
	//strncpy(buf, "First Message", sizeof(buf));
	//buf[sizeof(buf) - 1] = '\0';

	/* Say something to other side!!! */
	/*if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
		perror("write");
		exit(1);
	}*/
	//fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	//fflush(stdout);
	
	//printf("Before shutDown\n");	

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	/*if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}*/

	

	printf("Remote fd: %d, Local fd: %d\n",sd , 0 );

	printf("\n\nNew Session Started!!!\n\n\n");



	/* Read answer and write it to standard output */
	for (;;) {
		//printf("\n~~~~~~~~~~~~~~~~~~~~Client in loop again!!!!!!!!\n");
		
		 FD_ZERO(&socks);
		 FD_SET(sd,&socks);
		 FD_SET(STDIN_FILENO,&socks);
		 fprintf(stdout, "me: ");
		 fflush(stdout);
		 int readsocks = select(sd+1, &socks, NULL, NULL, NULL);

		 /* select() returns the number of sockets that had
			things going on with them -- i.e. they're readable. */
		
		/* Once select() returns, the original fd_set has been
			modified so it now reflects the state of why select()
			woke up. i.e. If file descriptor 4 was originally in
			the fd_set, and then it became readable, the fd_set
			contains file descriptor 4 in it. */
		
		if (readsocks < 0) {
			
			perror("select");
			exit(EXIT_FAILURE);
		}
		else{
				/* handle remote input */
				if (FD_ISSET(sd,&socks)){
					//printf("Checking remote buffer\n");
					n = read(sd, buf, sizeof(buf));
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
					if (insist_write(sd, buf, n) != n) {
						perror("write to remote  failed");
						break;

					}
					//printf("message sent\n");
				}

			  
			}

			

		
	}


	/* Make sure we don't leak open files */
	if (close(sd) < 0)
		perror("close");
	

	fprintf(stderr, "\nDone.\n");
	return 0;
}
