
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/filter.h>
#include <linux/cn_proc.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#include "lcmaps/lcmaps_log.h"
#include "proc_keeper.h"

int create_filter(int sock) {
    struct sock_filter filter[] = {
        BPF_STMT (BPF_LD|BPF_H|BPF_ABS,  // Accept packet if msg type != NLMSG_DONE
            offsetof (struct nlmsghdr, nlmsg_type)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
            htons (NLMSG_DONE),
            1, 0),
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS, // Only accept messages from the connector API.
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, id) + offsetof (struct cb_id, idx)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
            htonl (CN_IDX_PROC),
            1, 0),
        BPF_STMT (BPF_RET|BPF_K, 0x0),
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, id) + offsetof (struct cb_id, val)),
       BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
            htonl (CN_VAL_PROC),
            1, 0),
       BPF_STMT (BPF_RET|BPF_K, 0x0), 
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS, // If it is PROC_EVENT_EXIT, maybe accept the packet
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data) + offsetof (struct proc_event, what)),
       BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
            htonl (PROC_EVENT_EXIT),
            0, 7), // If not EXIT, jump to the fork case below.
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS, // Accept if the process_tgid == process_pid
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
            + offsetof (struct proc_event, event_data)
            + offsetof (struct exit_proc_event, process_pid)),
       BPF_STMT (BPF_ST, 0),
       BPF_STMT (BPF_LDX|BPF_W|BPF_MEM, 0),
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
            + offsetof (struct proc_event, event_data)
            + offsetof (struct exit_proc_event, process_tgid)),
       BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_X,
            0,
            1, 0),
       BPF_STMT (BPF_RET|BPF_K, 0x0),
       BPF_STMT (BPF_RET|BPF_K, 0xffffffff),
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS, // Only continue if this is a FORK event.
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data) + offsetof (struct proc_event, what)),
       BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
            htonl (PROC_EVENT_FORK),
            1, 0),
       BPF_STMT (BPF_RET|BPF_K, 0x0),
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS, // Accept if the child_tgid == child_pid
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
            + offsetof (struct proc_event, event_data)
            + offsetof (struct fork_proc_event, child_tgid)),
       BPF_STMT (BPF_ST, 0),
       BPF_STMT (BPF_LDX|BPF_W|BPF_MEM, 0),
       BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
            NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
            + offsetof (struct proc_event, event_data)
            + offsetof (struct fork_proc_event, child_pid)),
       BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_X,
            0,
            1, 0),
       BPF_STMT (BPF_RET|BPF_K, 0x0),
       BPF_STMT (BPF_RET|BPF_K, 0xffffffff)
    };

    struct sock_fprog fprog;
    fprog.filter = filter;
    fprog.len = sizeof filter / sizeof filter[0];

    if (setsockopt (sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof fprog) < 0) {
        lcmaps_log(0, "Unable to attach filter program: %d %s\n", errno, strerror(errno));
        return -errno;
    }
    return 0;
}

/**
 *  This borrows ideas and code (where possible) from:
 *    http://netsplit.com/2011/02/09/the-proc-connector-and-socket-filters/
 */

int create_socket() {
    int sock;
    sock = socket (PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock == -1) {
        lcmaps_log(0, "Unable to create a netlink socket: %d %s\n", errno, strerror(errno));
        return -errno;
    }

    // Set O_CLOEXEC
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)  {
        lcmaps_log(0, "Unable to get socket flags: %d %s\n", errno, strerror(errno));
        return -errno;
    }
    if (fcntl(sock, F_SETFL, flags | FD_CLOEXEC)< 0) {
        lcmaps_log(0, "Unable to manipulate socket flags: %d %s\n", errno, strerror(errno));
        return -errno;
    }

    struct sockaddr_nl addr;
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid ();
    addr.nl_groups = CN_IDX_PROC;

    int result = bind (sock, (struct sockaddr *)&addr, sizeof addr);
    if (result == -1) {
        lcmaps_log(0, "Unable to bind netlink socket to kernel: %d %s\n", errno, strerror(errno));
        return -errno;
    }

    unsigned int socket_size = 512*1024;
    if (setsockopt (sock, SOL_SOCKET, SO_RCVBUF, &socket_size, sizeof(int))) {
        lcmaps_log(0, "Unable to increase socket buffer size: %d %s\n", errno, strerror(errno));
        return -errno;
    }

    return sock;
}

/**
 * Subscribes to the feed from the proc connector
 */
int inform_kernel(int sock, enum proc_cn_mcast_op op) {

    struct iovec iov[3];
    char nlmsghdrbuf[NLMSG_LENGTH (0)];
    struct nlmsghdr *nlmsghdr = (struct nlmsghdr*)nlmsghdrbuf;
    struct cn_msg cn_msg;

    nlmsghdr->nlmsg_len = NLMSG_LENGTH (sizeof cn_msg + sizeof op);
    nlmsghdr->nlmsg_type = NLMSG_DONE;
    nlmsghdr->nlmsg_flags = 0;
    nlmsghdr->nlmsg_seq = 0;
    nlmsghdr->nlmsg_pid = getpid ();

    iov[0].iov_base = nlmsghdrbuf;
    iov[0].iov_len = NLMSG_LENGTH (0);

    cn_msg.id.idx = CN_IDX_PROC;
    cn_msg.id.val = CN_VAL_PROC;
    cn_msg.seq = 0;
    cn_msg.ack = 0;
    cn_msg.len = sizeof op;

    iov[1].iov_base = &cn_msg;
    iov[1].iov_len = sizeof cn_msg;

    iov[2].iov_base = &op;
    iov[2].iov_len = sizeof op;

    size_t full_size = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
    if (writev (sock, iov, 3) != full_size) {
        if (errno) {
            lcmaps_log(0, "Unable to subscribe to proc stream: %d %s\n", errno, strerror(errno));
            return -errno;
        }
        lcmaps_log(0, "Unable to write full subscription to kernel.");
        return -1;
    }

    return 0;
}

int message_loop(int sock) {

    struct msghdr msghdr;
    struct sockaddr_nl addr;
    struct iovec iov[1];
    char buf[getpagesize()];
    ssize_t len;

    msghdr.msg_name = &addr;
    msghdr.msg_namelen = sizeof addr;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = NULL;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags = 0;

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;

    struct nlmsghdr *nlmsghdr;

    while (1) {

        // If we think we are done, clear out the queued messages, then exit.
        len = recvmsg (sock, &msghdr, is_done() ? MSG_DONTWAIT : 0);

        if (len == -1) {
            if (errno == ENOBUFS) {
                lcmaps_log(0, "OVERFLOW (socket buffer overflow; likely fork bomb attack)");
            } else if (EAGAIN || EWOULDBLOCK) {
                // is_done was true, and we don't have any messages in the queue.
                break;
            } else {
                lcmaps_log(1, "Recovering from recvmsg error: %s\n", strerror(errno));
            }
            continue;
        }
        if (addr.nl_pid != 0) {
            continue;
        }

        for (nlmsghdr = (struct nlmsghdr *)buf;
                NLMSG_OK (nlmsghdr, len);
                 nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

            if ((nlmsghdr->nlmsg_type == NLMSG_ERROR) 
                    || (nlmsghdr->nlmsg_type == NLMSG_NOOP)) {
                lcmaps_log(1, "Ignoring message due to error.\n");
                continue;
            }

            struct cn_msg *cn_msg = NLMSG_DATA (nlmsghdr);
            if ((cn_msg->id.idx != CN_IDX_PROC)
                     || (cn_msg->id.val != CN_VAL_PROC)) {
                lcmaps_log(0, "Impossible message! %d.%d\n", cn_msg->id.idx, cn_msg->id.val);
                return -1;
            }

            struct proc_event *ev = (struct proc_event *)cn_msg->data;

            switch (ev->what) {

                case PROC_EVENT_FORK:
                    if (ev->event_data.fork.child_tgid == ev->event_data.fork.child_pid) {
                        //lcmaps_log(3, "DFORK: %d -> %d\n", ev->event_data.fork.parent_tgid, ev->event_data.fork.child_tgid);
                        processFork(ev->event_data.fork.parent_tgid, ev->event_data.fork.child_tgid);
                    }
                    break;
                case PROC_EVENT_EXIT:
                    if (ev->event_data.exit.process_tgid == ev->event_data.exit.process_pid) {
                        //lcmaps_log(3, "DEXIT: %d\n", ev->event_data.exit.process_tgid);
                        processExit(ev->event_data.exit.process_tgid);
                    }
                    break;
                default:
                    break; // Likely, the BPF isn't working correctly.
            }
        }

    }

    return 0;
}

