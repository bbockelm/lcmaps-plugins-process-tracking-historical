
#include <fcntl.h>
#include <sys/types.h>
#include <ext/hash_map>
#include <ext/hash_set>
#include <list>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

extern "C" {
#include "lcmaps/lcmaps_log.h"
}
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
        m_watched(watched),
        m_live_procs(1),
        m_started_shooting(false)
    {}
    int fork(pid_t, pid_t);
    int exit(pid_t);
    int shoot_tree();
    inline int is_done();
    inline pid_t get_pid() {return m_watched;}

private:
    PidSet m_ignored_pids;
    PidListMap m_pid_map;
    PidPidMap m_pid_reverse;
    pid_t m_watched;
    unsigned int m_live_procs;
    bool m_started_shooting;
    inline int record_new(pid_t, pid_t);
};

inline int ProcessTree::is_done() {
    return !m_live_procs;
}

inline int ProcessTree::record_new(pid_t parent_pid, pid_t child_pid) {
    lcmaps_log(3, "FORK %d -> %d\n", parent_pid, child_pid);
    m_live_procs++;
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
    } else if ((parent_pid != 1) && (it = m_pid_map.find(parent_pid)) != m_pid_map.end()) {
        lcmaps_log(3, "FORK %d -> %d\n", parent_pid, child_pid);
        m_live_procs++;
        (it->second).push_back(child_pid);
        m_pid_reverse[child_pid] = parent_pid;
        if (m_started_shooting) {
            shoot_tree();
        }
    } else if ((it2 = m_pid_reverse.find(parent_pid)) != m_pid_reverse.end()) {
        record_new(parent_pid, child_pid);
        if (m_started_shooting) {
            shoot_tree();
        }
    }else if (parent_pid == m_watched) {
        record_new(parent_pid, child_pid);
    }else {
        m_ignored_pids.insert(parent_pid);
        m_ignored_pids.insert(child_pid);
    }
    return 0;
}

int ProcessTree::shoot_tree() {
    m_started_shooting = true;

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
    if (body_count)
        lcmaps_log(2, "Cleaned all processes associated with %d\n", m_watched);
    return body_count;
}

int ProcessTree::exit(pid_t pid) {
    PidListMap::iterator it;
    PidPidMap::iterator it2;
    // The head process has died.  Start shooting
    if (pid == m_watched) {
        shoot_tree();
        lcmaps_log(2, "EXIT %d (main process)\n", pid);
        m_live_procs--;
    }
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
        m_live_procs--;
    }
    if ((it2 = m_pid_reverse.find(pid)) == m_pid_reverse.end()) {
        if (in_pid_map) {
            lcmaps_log(3, "EXIT %d\n");
            m_live_procs--;
        }
    } else {
        pid_t parent = it2->second;
        lcmaps_log(3, "EXIT %d PARENT %d\n", pid, parent);
        if ((it = m_pid_map.find(parent)) != m_pid_map.end()) {
            (it->second).remove(pid);
        }
        m_pid_reverse.erase(pid);
        m_live_procs--;
    }
    return 0;
}

ProcessTree *gTree;

int initialize(pid_t watch) {
    gTree = new ProcessTree(watch);
    return 0;
}

int is_done() {
    if (gTree)
        return gTree->is_done();
    return 1;
}

void finalize() {
    if (gTree) {
        if (!is_done()) {
            lcmaps_log(0, "ERROR: Finalizing without finishing killing the pid %d tree.\n", gTree->get_pid());
        }
        delete gTree;
    }
    gTree = NULL;
}

int processFork(pid_t parent_pid, pid_t child_pid) {
    return gTree->fork(parent_pid, child_pid);
}

int processExit(pid_t pid) {
    return gTree->exit(pid);
}

#pragma GCC visibility pop

