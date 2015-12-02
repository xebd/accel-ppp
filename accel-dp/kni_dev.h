#ifndef __KNI_DEV_H
#define __KNI_DEV_H

int kni_dev_count();
uint16_t kni_dev_rx_burst(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, const uint16_t nb_pkts);
uint16_t kni_dev_tx_burst(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

#endif

