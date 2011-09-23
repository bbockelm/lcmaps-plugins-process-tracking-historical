
#include <stdlib.h>
#include <linux/cn_proc.h>

int create_filter(int sock);
int create_socket();
int inform_kernel(int, enum proc_cn_mcast_op);
int message_loop(int);

