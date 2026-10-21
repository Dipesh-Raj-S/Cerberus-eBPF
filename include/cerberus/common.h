#ifndef CERBERUS_COMMON_H
#define CERBERUS_COMMON_H

/*
 * Global policy modes, stored in the policy_mode map.
 *
 *   CERBERUS_MODE_MONITOR
 *       Suspicious accesses are reported but never denied.
 *
 *   CERBERUS_MODE_ENFORCE
 *       Suspicious accesses are reported and denied with -EPERM.
 */
#define CERBERUS_MODE_MONITOR 0
#define CERBERUS_MODE_ENFORCE 1


/*
 * Rule types, stored in blocklist map values.
 *
 *   CERBERUS_RULE_NAME
 *       Key is a plain file name: "sensitive.txt".
 *
 *   CERBERUS_RULE_PATH
 *       Key is a fixed layout:
 *
 *           [0 .. 63]   parent directory name ("tmp")
 *           [64]        '/'
 *           [65 .. 255] file name ("sensitive.txt")
 *
 * File names can never contain '/', so the two
 * layouts can never collide inside the same map.
 */
#define CERBERUS_RULE_NAME 1
#define CERBERUS_RULE_PATH 2
#define CERBERUS_RULE_SANDBOX 3

#define CERBERUS_PATH_SLOT 64

/*
 * Wildcard UID for process-scoped rules.
 */
#define CERBERUS_UID_ANY 0xFFFFFFFFu


/*
 * Key for scoped deny rules and allowlist entries.
 *
 *   Process rule:  comm = "bash",  uid = CERBERUS_UID_ANY
 *   UID rule:      comm = "",      uid = 1000
 *   Allow entry:   comm = "bash",  uid = CERBERUS_UID_ANY
 *
 * "rule" holds a NAME or PATH rule key.
 */
struct scoped_rule_key {
    char comm[16];
    unsigned int uid;
    char rule[256];
};


/*
 * Event types sent through the ring buffer.
 */
#define CERBERUS_EVT_FILE_OPEN 1


/*
 * Value stored in the blocklist hash map.
 */
struct rule_value {
    unsigned char type; /* CERBERUS_RULE_* */
};


/*
 * Event structure shared between:
 *
 *   - the eBPF kernel program
 *   - the user-space Cerberus agent
 *
 * Both sides must interpret this structure
 * in exactly the same way.
 */
struct event {
    unsigned int pid;
    unsigned int uid;
    unsigned char denied;    /* 1 = blocked, 0 = monitor-only */
    unsigned char rule_type; /* CERBERUS_RULE_* */
    unsigned char evt_type;  /* CERBERUS_EVT_* */
    unsigned char reserved;
    char comm[16];
    char rule[256];          /* matched rule key (slot layout for path rules) */
};

#endif
