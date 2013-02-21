
// A simple header file defining the C interfaces for proc_keeper.cxx

#ifndef __PROC_KEEPER_H
#define __PROC_KEEPER_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int is_done();
void finalize();
int initialize(pid_t, pid_t);
int processFork(pid_t, pid_t);
int processExit(pid_t);
void processUsage();

#ifdef __cplusplus
}
#endif

#endif

