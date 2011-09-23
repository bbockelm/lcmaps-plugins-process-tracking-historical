
#include <fcntl.h>
#include <sys/types.h>
#include <ext/hash_map>
#include <ext/hash_set>
#include <list>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

#include "lcmaps/lcmaps_modules.h"
#include "proc_keeper.h"

#pragma GCC visibility push(hidden)

struct eqpid {
    bool operator()(const pid_t pid1, const pid_t pid2) const {
        return pid1 == pid2;
    }
};

typedef __gnu_cxx::hash_set<pid_t, __gnu_cxx::hash<pid_t>, eqpid> PidSet;
typedef __gnu_cxx::hash_map<pid_t, std::list<pid_t>, __gnu_cxx::hash<pid_t>, eqpid> PidListMap;
typedef __gnu_cxx::hash_map<pid_t, pid_t, __gnu_cxx::hash<pid_t>, eqpid> PidPidMap;
typedef std::list<pid_t> PidList;

class ProcessTree {

public:
    ProcessTree(pid_t watched) : 
        m_watched(watched)
    {}
    int fork(pid_t, pid_t);
    int exit(pid_t);
    int shoot_tree();

private:
    PidSet m_ignored_pids;
    PidListMap m_pid_map;
    PidPidMap m_pid_reverse;
    int m_watched;
    inline int record_new(pid_t, pid_t);
};

inline int ProcessTree::record_new(pid_t parent_pid, pid_t child_pid) {
    lcmaps_log(3, "FORK %d -> %d\n", parent_pid, child_pid);
    PidList pl;
    pl.push_back(child_pid);
    m_pid_map[parent_pid] = pl;
    m_pid_reverse[child_pid] = parent_pid;
    return 0;
}

int ProcessTree::fork(pid_t parent_pid, pid_t child_pid) {
    PidListMap::iterator it;
    PidPidMap::const_iterator it2;
    if (m_ignored_pids.find(parent_pid) != m_ignored_pids.end()) {
        return 0;
    } else if ((it = m_pid_map.find(parent_pid)) != m_pid_map.end()) {
        lcmaps_log(3, "FORK %d -> %d\n", parent_pid, child_pid);
        (it->second).push_back(child_pid);
        m_pid_reverse[child_pid] = parent_pid;
    } else if ((it2 = m_pid_reverse.find(parent_pid)) != m_pid_reverse.end()) {
        record_new(parent_pid, child_pid);
    }else if (parent_pid == m_watched) {
        record_new(parent_pid, child_pid);
    }
    return 0;
}

int ProcessTree::shoot_tree() {
    // Kill it all.
    PidListMap::const_iterator it;
    PidList::const_iterator it2, it3;
    // Check to see if there's children of this process.
    int body_count = 0;
    for (it = m_pid_map.begin(); it != m_pid_map.end(); ++it) {
        it3 = it->second.end();
        for (it2 = it->second.begin(); it2 != it3; ++it2) {
             if (*it2 == 1)
                 continue;
             if ((kill(*it2, SIGKILL) == -1) && (errno != ESRCH)) {
                 lcmaps_log(0, "FAILURE TO KILL %d: %d %s\n", *it2, errno, strerror(errno));
             }
             body_count ++;
        }
    }
    return body_count;
}

int ProcessTree::exit(pid_t pid) {
    PidListMap::iterator it;
    PidPidMap::iterator it2;
    if (m_ignored_pids.find(pid) != m_ignored_pids.end()) {
        m_ignored_pids.erase(pid);
        return 0;
    }
    int in_pid_map = false;
    if ((it = m_pid_map.find(pid)) != m_pid_map.end()) {
        in_pid_map = true;
        PidList::const_iterator it3;
        PidList &pl = it->second;
        // Check to see if there's children of this process.
        for (it3 = pl.begin(); it3 != pl.end(); ++it3) {
             // Re-parent the process to init.
             const pid_t child_pid = *it3;
             if ((it2 = m_pid_reverse.find(child_pid)) != m_pid_reverse.end()) {
                 lcmaps_log(1, "DAEMON %d\n", child_pid);
                 it2->second = 1;
             }
        }
        m_pid_map.erase(pid);
    }
    if ((it2 = m_pid_reverse.find(pid)) == m_pid_reverse.end()) {
        if (in_pid_map) {
            lcmaps_log(3, "EXIT %d\n");
        }
        return 0;
    } else {
        pid_t parent = it2->second;
        lcmaps_log(3, "EXIT %d PARENT %d\n", pid, parent);
        if ((it = m_pid_map.find(parent)) != m_pid_map.end()) {
            (it->second).remove(pid);
        }
        m_pid_reverse.erase(pid);
    }
    // The head process has died.  Start shooting
    if (pid == m_watched) {
        shoot_tree();
    }
    return 0;
}

ProcessTree *gTree;

int initialize(pid_t watch) {
    gTree = new ProcessTree(watch);
    return 0;
}

int try_finalize() {
    if (gTree)
        return gTree->shoot_tree();
    else
        return 0;
}

void finalize() {
    if (gTree)
        delete gTree;
    gTree = NULL;
}

int processFork(pid_t parent_pid, pid_t child_pid) {
    return gTree->fork(parent_pid, child_pid);
}

int processExit(pid_t pid) {
    return gTree->exit(pid);
}

#pragma GCC visibility pop

