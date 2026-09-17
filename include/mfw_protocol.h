#ifndef MFW_PROTOCOL_H
#define MFW_PROTOCOL_H

#include <stdint.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <linux/types.h>
#endif

#define MFW_DEVICE "/dev/mfw"

#define MFW_MAX_RULES 256

/* Address families */
#define MFW_AF_ANY   0
#define MFW_AF_INET  4
#define MFW_AF_INET6 6

/* Directions */
#define MFW_DIR_IN   1
#define MFW_DIR_OUT  2

/* Actions */
#define MFW_ACTION_DROP  0
#define MFW_ACTION_ALLOW 1

/* Protocols */
#define MFW_PROTO_ANY  0
#define MFW_PROTO_TCP  6
#define MFW_PROTO_UDP  17
#define MFW_PROTO_ICMP 1
#define MFW_PROTO_ICMPV6 58

/* Commands */
#define MFW_CMD_ADD       1
#define MFW_CMD_REMOVE    2
#define MFW_CMD_LIST      3
#define MFW_CMD_FLUSH     4
#define MFW_CMD_SET_POLICY 5
#define MFW_CMD_GET_POLICY 6

/* Default policy */
#define MFW_POLICY_ACCEPT 0
#define MFW_POLICY_DROP   1

struct mfw_addr {
    uint8_t family;
    uint8_t prefix;

    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } addr;
};

struct mfw_rule {
    uint32_t id;
    uint32_t priority;

    uint8_t direction;
    uint8_t action;
    uint8_t protocol;
    uint8_t reserved;

    struct mfw_addr source;
    struct mfw_addr destination;

    uint16_t source_port;
    uint16_t destination_port;
};

struct mfw_rule_stats {
    uint32_t id;

    uint64_t packets;
    uint64_t bytes;
};

struct mfw_ctl {
    uint8_t command;
    uint8_t reserved[3];

    union {
        struct mfw_rule rule;
        uint32_t rule_id;
        uint32_t policy;
    } data;
};

struct mfw_rule_info {
    struct mfw_rule rule;
    struct mfw_rule_stats stats;
};

#endif
