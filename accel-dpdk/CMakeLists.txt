include_directories(${DPDK}/build/include)

find_library(rte_eal NAMES librte_eal.a PATHS ${DPDK}/build/lib)
find_library(rte_malloc NAMES librte_malloc.a PATHS ${DPDK}/build/lib)
find_library(rte_mempool NAMES librte_mempool.a PATHS ${DPDK}/build/lib)
find_library(rte_ring NAMES librte_ring.a PATHS ${DPDK}/build/lib)

add_executable(accel-dpdk main.c)
target_link_libraries(accel-dpdk dl pthread
	-Wl,-whole-archive
	${rte_eal}
	${rte_mempool} 
	${rte_ring} 
	${rte_malloc} 
	-Wl,-no-whole-archive
)

