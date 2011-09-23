
/*
 * lcmaps-process-tracking
 * By Brian Bockelman, 2011 
 * This code is under the public domain
 */

/*****************************************************************************
                            Include header files
******************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>

#include "lcmaps/lcmaps_modules.h"
#include "lcmaps/lcmaps_cred_data.h"
#include "lcmaps/lcmaps_arguments.h"

#include "proc_police.h"
#include "proc_keeper.h"

char * logstr = "lcmaps-process-tracking";

// Daemonize the process
int do_daemonize() {

    //  Setting the real and effective uid/gid to root.
    if (setreuid(0, 0) != 0) {
      lcmaps_log_debug(0, "%s: Setting the real/effective uid to root failed: %d %s.\n", logstr, errno, strerror(errno));
      return -errno;
    }
  
    if (setregid(0, 0) != 0) {
      lcmaps_log_debug(0, "%s: Setting the real/effective gid to root failed: %d %s.\n", logstr, errno, strerror(errno));
      return -errno;
    }

    int pid = fork();
    if (pid < 0) {
        lcmaps_log(0, "%s: Fork failure: %d %s", logstr, errno, strerror(errno));
        return -errno;
    }
    if (pid > 0) {
        _exit(0);
    }
    umask(0);
    int sid = setsid();
    if (sid < 0) {
        lcmaps_log(0, "%s: Setsid failure: %d %s", logstr, errno, strerror(errno));
        return -errno;
    }
    if ((chdir("/")) < 0) {
        lcmaps_log(0, "%s: Chdir failure: %d %s", logstr, errno, strerror(errno));
        return -errno; 
    }
    // Note that fd 0/1 are used to talk to the parent; keep them open.
    close(2);
    open("/dev/null", O_RDONLY);
    
    return 0;
}

int proc_police_main(pid_t pid) {
    int result = 0;

    lcmaps_log(0, "%s: Process %d monitoring process %d\n", logstr, getpid(), pid);

    initialize(pid);

    // Create the netlink socket.
    int sock = create_socket();
    if (sock < 0) {
        result = sock;
        lcmaps_log(0, "%s: Unable to create socket.\n", logstr);
        goto cleanup;
    }
    lcmaps_log(3, "%s: Created netlink socket (%d) for kernel communication.\n", logstr, sock);

    // Create the filter for the socket
    if ((result = create_filter(sock)) < 0) {
        lcmaps_log(0, "%s: Unable to create filter.\n", logstr);
        goto cleanup;
    }
    lcmaps_log(3, "%s: Created netlink byte packet filter.\n", logstr);

    // Subscribe our socket to the kernel feed.
    if ((result = inform_kernel(sock, PROC_CN_MCAST_LISTEN)) < 0) {
        lcmaps_log(0, "%s: Unable to subscribe to the kernel stream\n", logstr);
        goto cleanup;
    }

    lcmaps_log(2, "%s: TRACKING %d\n", logstr, pid);
    write(1, "0", 1);
    close(1);
    open("/dev/null", O_WRONLY);
    close(0);
    open("/dev/null", O_RDONLY);

    // Primary message loop
    message_loop(sock);

    // Shutdown
    if ((result = inform_kernel(sock, PROC_CN_MCAST_IGNORE)) < 0) {
        lcmaps_log(0, "%s: Unable to unsubscribe from the kernel stream.\n", logstr);
        goto cleanup;
    }

cleanup:
    finalize();
    if (sock >= 0) {
        close(sock);
    }
    lcmaps_log(0, "%s: Process %d (monitoring process %d) finished with code %d.\n", logstr, getpid(), pid, result);
    return result;
}

void handle_child(int p2c[], int c2p[], pid_t pid)
{
    // Close all file handles.
    //  Child Process
    close(p2c[1]);
    close(c2p[0]);
    if (dup2(p2c[0], 0) == -1) {
      lcmaps_log(0, "%s: Failed to dup file descriptor (%d: %s)\n", errno, strerror(errno));
      exit(errno);
    }
    if (dup2(c2p[1], 1) == -1) {
      lcmaps_log(0, "%s: Failed to dup file descriptor (%d: %s)\n", errno, strerror(errno));
      exit(errno);
    }
    close(p2c[0]);
    close(p2c[1]);
    close(c2p[1]);

    //  Setting the real and effective uid/gid to root.
    if (setreuid(0, 0) != 0) {
      lcmaps_log_debug(0, "%s: Setting the real/effective uid to root failed.\n", logstr);
      exit(errno);
    }

    if (setregid(0, 0) != 0) {
      lcmaps_log_debug(0, "%s: Setting the real/effective gid to root failed.\n", logstr);
      exit(errno);
    }
    if (do_daemonize()) {
      lcmaps_log_debug(0, "%s: Failed to daemonize!\n", logstr);
      exit(1);
    }
    
    int result = proc_police_main(pid);
    exit(result);
}

/******************************************************************************
Function:   plugin_initialize
Description:
    Initialize plugin; a no-op, but required by LCMAPS
Parameters:
    argc, argv
    argv[0]: the name of the plugin
Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_initialize(int argc, char **argv)
{

  return LCMAPS_MOD_SUCCESS;

}


/******************************************************************************
Function:   plugin_introspect
Description:
    return list of required arguments
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_introspect(int *argc, lcmaps_argument_t **argv)
{
  char *logstr = "\tlcmaps_plugins_glexec_tracking-plugin_introspect()";
  static lcmaps_argument_t argList[] = {
    {NULL        ,  NULL    , -1, NULL}
  };

  lcmaps_log_debug(2, "%s: introspecting\n", logstr);

  *argv = argList;
  *argc = lcmaps_cntArgs(argList);
  lcmaps_log_debug(1, "%s: address first argument: 0x%x\n", logstr, argList);

  lcmaps_log_debug(1, "%s: Introspect succeeded\n", logstr);

  return LCMAPS_MOD_SUCCESS;
}




/******************************************************************************
Function:   plugin_run
Description:
    Launch a process tracking daemon for LCMAPS.
    Basic boilerplate for a LCMAPS plugin.
Parameters:
    argc: number of arguments
    argv: list of arguments
Returns:
    LCMAPS_MOD_SUCCESS: authorization succeeded
    LCMAPS_MOD_FAIL   : authorization failed
******************************************************************************/
int plugin_run(int argc, lcmaps_argument_t *argv)
{
  FILE *fh = NULL;
  int p2c[2], c2p[2];
  int rc = 0, ok = 0;
  int uid_count;
  uid_t uid;
  pid_t pid, my_pid;

  uid_count = 0;
  uid_t * uid_array;
  uid_array = (uid_t *)getCredentialData(UID, &uid_count);
  if (uid_count != 1) {
    lcmaps_log(0, "%s: No UID set yet; must map to a UID before running the glexec_tracking module.\n", logstr);
    goto glexec_uid_failure;
  }
  uid = uid_array[0];

  if (pipe(p2c) == -1) {
    lcmaps_log(0, "%s: Pipe creation failure (%d: %s)\n", errno, strerror(errno));
    goto glexec_pipe_failure;
  }
  if (pipe(c2p) == -1) {
    lcmaps_log(0, "%s: Pipe creation failure (%d: %s)\n", errno, strerror(errno));
    goto glexec_pipe_failure;
  }

  my_pid = getpid();

  pid = fork();
  if (pid == -1) {
    lcmaps_log(0, "%s: Fork failure (%d: %s)\n", errno, strerror(errno));
    goto glexec_fork_failure;
  } else if (pid == 0) {
    handle_child(p2c, c2p, my_pid);
  }
  close(p2c[0]);
  close(p2c[1]);
  close(c2p[1]);

  //  After dumping the string to stdout, we need to expect an answer
  //  back on stdin.
  fh = fdopen(c2p[0], "r");
  if (fh == NULL) {
    rc = 1;
  } else {
    rc = fscanf(fh, "%d", &ok);
    fclose(fh);
  }

  if (rc < 0) {
     lcmaps_log (0, "Error: failure reading from the monitor process. %d.\n", rc);
     goto glexec_child_failure;
  }
  if (ok != 0) {
     lcmaps_log (0, "Error: failure in configuring monitor process. %d.\n", ok);
     goto glexec_child_failure;
  }

  lcmaps_log(0, "%s: glexec_tracking plugin succeeded\n", logstr);

  return LCMAPS_MOD_SUCCESS;


glexec_fork_failure:
  close(p2c[0]);
  close(p2c[1]);
  close(c2p[0]);
  close(c2p[1]);
glexec_pipe_failure:
glexec_uid_failure:
glexec_child_failure:
  lcmaps_log_time(0, "%s: glexec_tracking plugin failed\n", logstr);

  return LCMAPS_MOD_FAIL;
}

int plugin_verify(int argc, lcmaps_argument_t * argv)
{
    return plugin_run(argc, argv);
}

/******************************************************************************
Function:   plugin_terminate
Description:
    Terminate plugin.  Boilerplate - doesn't do anything
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_terminate()
{
  return LCMAPS_MOD_SUCCESS;
}
