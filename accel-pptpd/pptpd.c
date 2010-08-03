/*
*  C Implementation: pptpd
*
* Description:
*
*
* Author:  <xeb@mail.ru>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "list.h"
#include "pptp_prot.h"
#include "triton/triton.h"
#include "pptpd.h"
#include "log.h"

static struct ctrl_thread_t *threads=NULL;
static int threads_count=0;

int start_server(void)
{
  int sock,c_sock;
  int r,min_thr,min_cnt;
  struct pollfd pfd;
  struct sockaddr_in addr;
	socklen_t size;

  sock=socket (PF_INET, SOCK_STREAM, 0);
  if (sock<0)
  {
    log_error("failed to create socket\n");
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons (PPTP_PORT);
  addr.sin_addr.s_addr = htonl (INADDR_ANY);
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sock, sizeof(sock));
  if (bind (sock, (struct sockaddr *) &addr, sizeof (addr)) < 0)
  {
  	perror("bind");
    log_error("failed to bind socket\n");
    return -1;
  }

  if (listen (sock, 1000)<0)
  {
    log_error("failed to listen socket\n");
    return -1;
  }

	pfd.fd=sock;
	pfd.events=POLLIN;

	while(1)
	{
		r=poll(&pfd,1,-1);
		if (r<0 && errno!=EINTR)
		{
	    log_error("poll failed\n");
  	  return -2;
		}
		if (r<=0) continue;
  	if (!(pfd.revents&POLLIN)) continue;

  	size=sizeof(addr);
		c_sock=accept(sock,(struct sockaddr *)&addr,&size);
		if (c_sock<0)
		{
			log_error("client accept failed\n");
			continue;
		}

		min_thr=0; min_cnt=65536;
		for(r=0; r<threads_count; r++)
		{
			pthread_mutex_lock(&threads[r].lock);
			if (threads[r].count<min_cnt)
			{
				min_cnt=threads[r].count;
				min_thr=r;
			}
			pthread_mutex_unlock(&threads[r].lock);
		}
		write(threads[min_thr].pipe_fd[1],&c_sock,sizeof(c_sock));
	}
}

int start_threads(int cnt)
{
	int i;
	if (!cnt) cnt=sysconf(_SC_NPROCESSORS_CONF);
	threads=malloc(cnt*sizeof(*threads));
	memset(threads,0,cnt*sizeof(*threads));

	for(i=0; i<cnt; i++)
	{
		//threads[i].lock=PTHREAD_MUTEX_INITIALIZER;
		if (pipe(threads[i].pipe_fd))
		{
			log_error("failed to create pipe\n");
			return -1;
		}
		if (triton_run((int(*)(void*))ctrl_init,&threads[i]))
		{
			log_error("triton_run failed\n");
			return -1;
		}
	}
	threads_count=cnt;
	return 0;
}

int main(int argc,char **argv)
{
	log_init(stdout,4,0);
	start_threads(0);
	start_server();
	return EXIT_SUCCESS;
}
