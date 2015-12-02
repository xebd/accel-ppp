set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

add_definitions("-DACCEL_DP")

include_directories(${DPDK}/build/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_library(rte_eal NAMES librte_eal.a PATHS ${DPDK}/build/lib)
find_library(rte_malloc NAMES librte_malloc.a PATHS ${DPDK}/build/lib)
find_library(rte_mbuf NAMES librte_mbuf.a PATHS ${DPDK}/build/lib)
find_library(rte_mempool NAMES librte_mempool.a PATHS ${DPDK}/build/lib)
find_library(rte_ring NAMES librte_ring.a PATHS ${DPDK}/build/lib)
find_library(ethdev NAMES libethdev.a PATHS ${DPDK}/build/lib)
find_library(rte_kni NAMES librte_kni.a PATHS ${DPDK}/build/lib)
find_library(rte_distributor NAMES librte_distributor.a PATHS ${DPDK}/build/lib)
find_library(rte_pmd_virtio NAMES librte_pmd_virtio.a PATHS ${DPDK}/build/lib)

add_executable(accel-dp
	main.c
	conf_file.c
	event.c
	ctrl.c
	af_packet.c
	dev.c
	eth_dev.c
	kni_dev.c
	distributor.c

	log.c
	log_file.c

	libnetlink.c
	iputils.c
)

target_link_libraries(accel-dp dl pthread
	-Wl,-whole-archive
	${rte_eal}
	${rte_mbuf} 
	${rte_mempool} 
	${rte_ring} 
	${rte_malloc} 
	${ethdev}
	${rte_kni}
	${rte_distributor}
	${rte_pmd_virtio}
	-Wl,-no-whole-archive
)

