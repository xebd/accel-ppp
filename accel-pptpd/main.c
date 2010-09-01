#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "triton/triton.h"

void sigterm(int num)
{
}
int main(int argc,char **argv)
{
	int i;
	int daemon=0;
	char *pid_file=NULL;
	char *conf_file=NULL;
	sigset_t set;

	if (argc<2)
		goto usage;

	for(i=1; i<argc; i++)
	{
		if (!strcmp(argv[i],"-d"))
			daemon=1;
		else if (!strcmp(argv[i],"-p"))
		{
			if (i==argc-1)
				goto usage;
			pid_file=argv[++i];
		}
		else if (!strcmp(argv[i],"-c"))
		{
			if (i==argc-1)
				goto usage;
			conf_file=argv[++i];
		}
	}

	if (!conf_file)
		goto usage;

	if (triton_init(conf_file))
		return EXIT_FAILURE;
	
	if (daemon)
	{
		pid_t pid=fork();
		if (pid>0)
			_exit(EXIT_SUCCESS);
		if (pid<0)
		{
			perror("fork");
			return EXIT_FAILURE;
		}
		if (setsid()<0)
			return EXIT_FAILURE;
		pid=fork();
		if (pid)
			_exit(0);
		umask(0);
		chdir("/");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	if (pid_file)
	{
		FILE *f=fopen("pid_file","w");
		if (f)
		{
			fprintf(f,"%i",getpid());
			fclose(f);
		}
	}

	triton_run();
	
	signal(SIGTERM,sigterm);
	sigfillset(&set);
	sigdelset(&set, SIGTERM);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGBUS);

	sigsuspend(&set);
	
	triton_terminate();

	return EXIT_SUCCESS;
usage:
	printf("usage: pptpd [-d] [-p <file>] -c <file>\
	where:\
		-d - daemon mode\
		-p - write pid to <file>\
		-c - config file\n");
	return EXIT_FAILURE;
}

