#ifndef __COMMON_H
#define __COMMON_H

struct event {
    int pid;
    char comm[16];
    char filename[256];
};

#endif
