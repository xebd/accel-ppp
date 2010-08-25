#include "triton/triton.h"
#include "log.h"

void sigterm(int num)
{
	triton_terminate();
}
int main(int argc,char **argv)
{
	sigset_t set;

	log_init(stdout,4,0);
	
	triton_init();
	triton_run();
	
	signal(SIGTERM,sigterm);
	sigfillset(&set);
	sigdelset(&set, SIGTERM);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGBUS);

	sigsuspend(&set);

	return EXIT_SUCCESS;
}

