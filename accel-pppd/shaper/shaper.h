#ifndef __SHAPER_H
#define __SHAPER_H

#define LIM_POLICE 0
#define LIM_TBF 1
#define LIM_HTB 2

extern int conf_up_limiter;
extern int conf_down_limiter;

extern double conf_down_burst_factor;
extern double conf_up_burst_factor;
extern double conf_latency;
extern int conf_mpu;
extern int conf_quantum;
extern int conf_r2q;
extern int conf_ifb_ifindex;

int install_limiter(struct ppp_t *ppp, int down_speed, int down_burst, int up_speed, int up_burst);
int remove_limiter(struct ppp_t *ppp);
int init_ifb(const char *);

#endif
