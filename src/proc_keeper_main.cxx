
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <limits.h>

extern "C" {
#include "proc_police.h"
#include "proc_keeper.h"
}

int proc_police_main(pid_t pid, pid_t parent_pid) {
    int result = 0;

    syslog(LOG_INFO, "Process %d monitoring process %d\n", getpid(), pid);

    initialize(pid, parent_pid);

    // Create the netlink socket.
    int sock = create_socket();
    if (sock < 0) {
        result = sock;
        syslog(LOG_ERR, "Unable to create socket.\n");
        goto cleanup;
    }
    //syslog(LOG_DEBUG, "Created netlink socket (%d) for kernel communication.\n", sock);

    // Create the filter for the socket
    if ((result = create_filter(sock)) < 0) {
        syslog(LOG_ERR, "Unable to create filter.\n");
        goto cleanup;
    }
    //syslog(LOG_DEBUG, "Created netlink byte packet filter.\n");

    // Subscribe our socket to the kernel feed.
    if ((result = inform_kernel(sock, PROC_CN_MCAST_LISTEN)) < 0) {
        syslog(LOG_ERR, "Unable to subscribe to the kernel stream\n");
        goto cleanup;
    }

    syslog(LOG_NOTICE, "TRACKING %d\n", pid);

    // Re-open syslog without logging to stderr.
    closelog();
    openlog("process-tracking", LOG_NDELAY|LOG_PID, LOG_DAEMON);

    // Inform parent we've started up.
    int rc;
    while (((rc = write(1, "0", 1)) < 0) && errno == EINTR) {}
    if (rc != 1) {
        syslog(LOG_ERR, "Unable to write result to parent.\n");
        goto cleanup;
    }
    close(1);
    open("/dev/null", O_WRONLY);
    close(0);
    open("/dev/null", O_RDONLY);

    // Primary message loop
    message_loop(sock);

    // Shutdown
    if ((result = inform_kernel(sock, PROC_CN_MCAST_IGNORE)) < 0) {
        syslog(LOG_ERR, "Unable to unsubscribe from the kernel stream.\n");
        goto cleanup;
    }

cleanup:
    finalize();
    if (sock >= 0) {
        close(sock);
    }
    syslog(LOG_NOTICE, "Process %d (monitoring process %d) finished with code %d.\n", getpid(), pid, result);
    return result;
}

pid_t get_max_pid() {

    int rc;
    long pid;
    FILE *fp;
    char buf[512];
    if ((fp = fopen("/proc/sys/kernel/pid_max", "r")) == NULL) {
        syslog(LOG_ERR, "Unable to open /proc/sys/kernel/pid_max: (errno=%d) %s\n", errno, strerror(errno));
        return -1;
    }
    if (fgets(buf, 512, fp) == NULL) {
        if (ferror(fp)) {
            syslog(LOG_ERR, "Error reading from /proc/sys/kernel/pid_max: (errno=%d) %s\n", errno, strerror(errno));
        } else {
            syslog(LOG_ERR, "Empty /proc/sys/kernel/pid_max.\n");
        }
        fclose(fp);
        rc = -1;
        goto cleanup;
    }

    errno = 0;
    pid = strtol(buf, NULL, 10);
    if (((pid == 0) || (pid == LONG_MAX) || (pid == LONG_MIN)) && (errno != 0)) {
        // Note no newline at the end of log message, as fgets should end the file with a newline.
        syslog(LOG_ERR, "Invalid contents of /proc/sys/kernel/pid_max: %s", buf);
        rc = -1;
        goto cleanup;
    }
    rc = pid;

cleanup:
    fclose(fp);
    return rc;

}

int get_fd_max() {
    DIR * dir;
    int rc = -1;
    if ((dir = opendir("/proc/self/fd")) == NULL) {
        syslog(LOG_ERR, "Unable to read /proc/self/fd: (errno=%d) %s.\n", errno, strerror(errno));
        return -1;
    }

    struct dirent *dp;
    int max_fd = -1;
    do {
        errno = 0;
        if ((dp = readdir(dir)) != NULL) {
            long fd = strtol(dp->d_name, NULL, 10);
            if ((fd < 0) || (((fd == 0) || (fd == LONG_MAX) || (fd == LONG_MIN)) && (errno != 0))) {
                syslog(LOG_ERR, "Error parsing /proc/self/fd entry: %s (%s).\n", dp->d_name, strerror(errno));
                rc = -1;
                goto cleanup;
            }
            if (fd > max_fd) {
                max_fd = fd;
            }
        }
    } while (dp != NULL);

    if (errno != 0) {
        syslog(LOG_ERR, "Error reading /proc/self/fd: (errno=%d) %s.\n", errno, strerror(errno));
        rc = -1;
    } else {
        rc = max_fd;
    }

cleanup:
    closedir(dir);
    return rc;
}

int main(int argc, char *argv[]) {

    // While we are processing arguments and starting up, log to stderr.
    openlog("process-tracking", LOG_PID|LOG_PERROR, LOG_DAEMON);

    // Input parsing and sanitation
    if (argc != 3) {
        syslog(LOG_ERR, "Usage: process-tracking <pid> <ppid>\n");
        syslog(LOG_ERR, "Not enough arguments!\n");
        return 1;
    }
    pid_t pid_max = get_max_pid();
    errno = 0;
    long pid = strtol(argv[1], NULL, 10);
    if (((pid == 0) || (pid == LONG_MAX) || (pid == LONG_MIN)) && (errno != 0)) {
        syslog(LOG_ERR, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    long ppid = strtol(argv[2], NULL, 10);
    if (((ppid == 0) || (ppid == LONG_MAX) || (ppid == LONG_MIN)) && (errno != 0)) {
        syslog(LOG_ERR, "Invalid PID: %s\n", argv[2]);
        return 1;
    }
    if ((pid <= 1) || (pid > pid_max)) {
        syslog(LOG_ERR, "PID outside valid range [2, %d]: %ld", pid_max, pid);
        return 1;
    }
    if ((ppid <= 1) || (ppid > pid_max)) {
        syslog(LOG_ERR, "PID outside valid range [2, %d]: %ld", pid_max, ppid);
        return 1;
    }

    // Close out unused fds.  LCMAPS shouldn't leak FDs to us, but just in
    // case...
    int max_fd = get_fd_max();
    syslog(LOG_DEBUG, "Max FD: %d.\n", max_fd);
    if (max_fd < 0) {
        return 1;
    }
    // 0 and 1 are closed in proc_polic_main; 2 is closed in 
    // lcmaps_proc_tracking.c's do_daemonize.
    int idx;
    for (idx = 3; idx<=max_fd; idx++) {
        syslog(LOG_DEBUG, "Closing FD: %d\n", idx);
        close(idx); // Ignore exit.
    }

    int rc = proc_police_main(pid, ppid);

    closelog();

    return rc;

}

