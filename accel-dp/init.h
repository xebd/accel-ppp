#ifndef __INIT_H
#define __INIT_H

struct rte_mempool;

int ctrl_init();
int kni_dev_init(struct rte_mempool *mbuf_pool);
int eth_dev_init(struct rte_mempool *mbuf_pool);

int distributor_init(int ded);
void distributor_loop(int chk_event);
int lcore_worker(void *a);
int lcore_distributor(void *a);

void register_init(int order, void (*func)(void));
#define DEFINE_INIT(o, func) static void __attribute__((constructor)) __init__(void){register_init(o,func);}

#endif
