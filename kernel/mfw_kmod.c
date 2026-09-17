#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/string.h>

#include "mfw_kmod.h"

#define DEVICE_NAME "mfw"
#define CLASS_NAME  "mfw_class"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiniFirewall Unified");
MODULE_DESCRIPTION("Unified IPv4/IPv6 C++ MiniFirewall");
MODULE_VERSION("2.0");

struct kernel_rule {
    struct mfw_rule rule;

    atomic64_t packets;
    atomic64_t bytes;
};

static struct kernel_rule rule_list[MFW_MAX_RULES];
static unsigned int rule_count;

static unsigned int default_policy = MFW_POLICY_ACCEPT;

static DEFINE_SPINLOCK(rule_lock);

static int major;
static struct class *mfw_class;
static struct device *mfw_device;


/* ============================================================
 * Address matching
 * ============================================================
 */

static bool match_ipv4(
    const struct mfw_addr *rule_addr,
    __be32 packet_addr
)
{
    __u32 rule_ip;
    __u32 packet_ip;
    __u32 mask;

    if (rule_addr->family == MFW_AF_ANY)
        return true;

    if (rule_addr->family != MFW_AF_INET)
        return false;

    if (rule_addr->prefix > 32)
        return false;

    rule_ip = ntohl(rule_addr->addr.ipv4);
    packet_ip = ntohl(packet_addr);

    if (rule_addr->prefix == 0)
        return true;

    mask = 0xFFFFFFFFU << (32 - rule_addr->prefix);

    return (rule_ip & mask) == (packet_ip & mask);
}


static bool match_ipv6(
    const struct mfw_addr *rule_addr,
    const struct in6_addr *packet_addr
)
{
    unsigned int prefix;
    unsigned int full_bytes;
    unsigned int remaining_bits;

    if (rule_addr->family == MFW_AF_ANY)
        return true;

    if (rule_addr->family != MFW_AF_INET6)
        return false;

    if (rule_addr->prefix > 128)
        return false;

    prefix = rule_addr->prefix;

    full_bytes = prefix / 8;
    remaining_bits = prefix % 8;

    if (full_bytes > 0) {
        if (memcmp(
                rule_addr->addr.ipv6,
                packet_addr->s6_addr,
                full_bytes) != 0) {
            return false;
        }
    }

    if (remaining_bits > 0) {
        __u8 mask;
        __u8 rule_byte;
        __u8 packet_byte;

        mask = 0xFF << (8 - remaining_bits);

        rule_byte = rule_addr->addr.ipv6[full_bytes];
        packet_byte = packet_addr->s6_addr[full_bytes];

        if ((rule_byte & mask) != (packet_byte & mask))
            return false;
    }

    return true;
}


/* ============================================================
 * Transport header matching
 * ============================================================
 */

static bool match_ports(
    const struct mfw_rule *rule,
    struct sk_buff *skb,
    unsigned int transport_offset,
    __u8 protocol
)
{
    __be16 source_port;
    __be16 destination_port;

    if (rule->source_port == 0 &&
        rule->destination_port == 0) {
        return true;
    }

    if (protocol != MFW_PROTO_TCP &&
        protocol != MFW_PROTO_UDP) {
        return false;
    }

    if (skb_copy_bits(
            skb,
            transport_offset,
            &source_port,
            sizeof(source_port)) < 0) {
        return false;
    }

    if (skb_copy_bits(
            skb,
            transport_offset + sizeof(source_port),
            &destination_port,
            sizeof(destination_port)) < 0) {
        return false;
    }

    if (rule->source_port != 0 &&
        rule->source_port != ntohs(source_port)) {
        return false;
    }

    if (rule->destination_port != 0 &&
        rule->destination_port != ntohs(destination_port)) {
        return false;
    }

    return true;
}


/* ============================================================
 * IPv4 packet matching
 * ============================================================
 */

static bool match_ipv4_packet(
    const struct mfw_rule *rule,
    struct sk_buff *skb
)
{
    struct iphdr *iph;
    unsigned int header_length;

    iph = ip_hdr(skb);

    if (!iph)
        return false;

    header_length = iph->ihl * 4;

    if (header_length < sizeof(struct iphdr))
        return false;

    if (!match_ipv4(&rule->source, iph->saddr))
        return false;

    if (!match_ipv4(&rule->destination, iph->daddr))
        return false;

    if (rule->protocol != MFW_PROTO_ANY &&
        rule->protocol != iph->protocol) {
        return false;
    }

    if (rule->source_port != 0 ||
        rule->destination_port != 0) {

        if (!match_ports(
                rule,
                skb,
                header_length,
                iph->protocol)) {
            return false;
        }
    }

    return true;
}


/* ============================================================
 * IPv6 packet matching
 * ============================================================
 */

static bool match_ipv6_packet(
    const struct mfw_rule *rule,
    struct sk_buff *skb
)
{
    struct ipv6hdr *ip6h;

    ip6h = ipv6_hdr(skb);

    if (!ip6h)
        return false;

    if (!match_ipv6(
            &rule->source,
            &ip6h->saddr)) {
        return false;
    }

    if (!match_ipv6(
            &rule->destination,
            &ip6h->daddr)) {
        return false;
    }

    if (rule->protocol != MFW_PROTO_ANY &&
        rule->protocol != ip6h->nexthdr) {
        return false;
    }

    if (rule->source_port != 0 ||
        rule->destination_port != 0) {

        if (!match_ports(
                rule,
                skb,
                sizeof(struct ipv6hdr),
                ip6h->nexthdr)) {
            return false;
        }
    }

    return true;
}


/* ============================================================
 * General rule matching
 * ============================================================
 */

static bool match_rule(
    const struct mfw_rule *rule,
    struct sk_buff *skb,
    const struct nf_hook_state *state
)
{
    bool ipv6;

    if (rule->direction == MFW_DIR_IN) {
        if (state->hook != NF_INET_LOCAL_IN)
            return false;
    }

    if (rule->direction == MFW_DIR_OUT) {
        if (state->hook != NF_INET_LOCAL_OUT)
            return false;
    }

    ipv6 = state->pf == PF_INET6;

    if (ipv6)
        return match_ipv6_packet(rule, skb);

    return match_ipv4_packet(rule, skb);
}


/* ============================================================
 * Netfilter hook
 * ============================================================
 */

static unsigned int firewall_hook(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
)
{
    unsigned int i;
    unsigned int result;

    result = default_policy == MFW_POLICY_DROP
        ? NF_DROP
        : NF_ACCEPT;

    spin_lock_bh(&rule_lock);

    for (i = 0; i < rule_count; i++) {

        struct kernel_rule *kr;

        kr = &rule_list[i];

        if (!match_rule(
                &kr->rule,
                skb,
                state)) {
            continue;
        }

        atomic64_inc(&kr->packets);
        atomic64_add(
            skb->len,
            &kr->bytes);

        if (kr->rule.action == MFW_ACTION_DROP)
            result = NF_DROP;
        else
            result = NF_ACCEPT;

        break;
    }

    spin_unlock_bh(&rule_lock);

    return result;
}


/* ============================================================
 * Netfilter hooks
 * ============================================================
 */

static struct nf_hook_ops ipv4_input_hook = {
    .hook = firewall_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops ipv4_output_hook = {
    .hook = firewall_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops ipv6_input_hook = {
    .hook = firewall_hook,
    .pf = PF_INET6,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP6_PRI_FIRST
};

static struct nf_hook_ops ipv6_output_hook = {
    .hook = firewall_hook,
    .pf = PF_INET6,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP6_PRI_FIRST
};


/* ============================================================
 * Rule validation
 * ============================================================
 */

static int validate_rule(
    const struct mfw_rule *rule
)
{
    if (rule->direction != MFW_DIR_IN &&
        rule->direction != MFW_DIR_OUT) {
        return -EINVAL;
    }

    if (rule->action != MFW_ACTION_DROP &&
        rule->action != MFW_ACTION_ALLOW) {
        return -EINVAL;
    }

    if (rule->source.family != MFW_AF_ANY &&
        rule->source.family != MFW_AF_INET &&
        rule->source.family != MFW_AF_INET6) {
        return -EINVAL;
    }

    if (rule->destination.family != MFW_AF_ANY &&
        rule->destination.family != MFW_AF_INET &&
        rule->destination.family != MFW_AF_INET6) {
        return -EINVAL;
    }

    if (rule->source.family == MFW_AF_INET &&
        rule->source.prefix > 32) {
        return -EINVAL;
    }

    if (rule->destination.family == MFW_AF_INET &&
        rule->destination.prefix > 32) {
        return -EINVAL;
    }

    if (rule->source.family == MFW_AF_INET6 &&
        rule->source.prefix > 128) {
        return -EINVAL;
    }

    if (rule->destination.family == MFW_AF_INET6 &&
        rule->destination.prefix > 128) {
        return -EINVAL;
    }

    if (rule->source_port != 0 ||
        rule->destination_port != 0) {

        if (rule->protocol != MFW_PROTO_TCP &&
            rule->protocol != MFW_PROTO_UDP) {
            return -EINVAL;
        }
    }

    if (rule->source.family != MFW_AF_ANY &&
        rule->destination.family != MFW_AF_ANY &&
        rule->source.family != rule->destination.family) {
        return -EINVAL;
    }

    return 0;
}


/* ============================================================
 * Duplicate rule detection
 * ============================================================
 */

static bool rule_equal(
    const struct mfw_rule *a,
    const struct mfw_rule *b
)
{
    return memcmp(a, b, sizeof(struct mfw_rule)) == 0;
}


static bool duplicate_rule(
    const struct mfw_rule *rule
)
{
    unsigned int i;

    for (i = 0; i < rule_count; i++) {
        if (rule_equal(
                &rule_list[i].rule,
                rule)) {
            return true;
        }
    }

    return false;
}


/* ============================================================
 * Add rule
 * ============================================================
 */

static int add_rule(
    const struct mfw_rule *rule
)
{
    unsigned int i;

    if (rule_count >= MFW_MAX_RULES)
        return -ENOSPC;

    if (validate_rule(rule) < 0)
        return -EINVAL;

    if (duplicate_rule(rule))
        return -EEXIST;

    rule_list[rule_count].rule = *rule;

    atomic64_set(
        &rule_list[rule_count].packets,
        0);

    atomic64_set(
        &rule_list[rule_count].bytes,
        0);

    /*
     * Automatically assign an ID if the
     * user did not provide one.
     */
    if (rule_list[rule_count].rule.id == 0) {

        for (i = 1; i <= MFW_MAX_RULES; i++) {
            unsigned int j;
            bool used = false;

            for (j = 0; j < rule_count; j++) {
                if (rule_list[j].rule.id == i) {
                    used = true;
                    break;
                }
            }

            if (!used) {
                rule_list[rule_count].rule.id = i;
                break;
            }
        }
    }

    rule_count++;

    return 0;
}


/* ============================================================
 * Remove rule
 * ============================================================
 */

static int remove_rule(
    uint32_t id
)
{
    unsigned int i;

    for (i = 0; i < rule_count; i++) {

        if (rule_list[i].rule.id != id)
            continue;

        if (i < rule_count - 1) {
            memmove(
                &rule_list[i],
                &rule_list[i + 1],
                (rule_count - i - 1) *
                sizeof(struct kernel_rule));
        }

        memset(
            &rule_list[rule_count - 1],
            0,
            sizeof(struct kernel_rule));

        rule_count--;

        return 0;
    }

    return -ENOENT;
}


/* ============================================================
 * Device read
 * ============================================================
 */

static ssize_t mfw_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *offset
)
{
    struct mfw_rule_info info;
    unsigned int index;

    if (count < sizeof(info))
        return -EINVAL;

    index =
        (*offset) / sizeof(info);

    spin_lock_bh(&rule_lock);

    if (index >= rule_count) {
        spin_unlock_bh(&rule_lock);
        return 0;
    }

    memset(&info, 0, sizeof(info));

    info.rule =
        rule_list[index].rule;

    info.stats.id =
        rule_list[index].rule.id;

    info.stats.packets =
        atomic64_read(
            &rule_list[index].packets);

    info.stats.bytes =
        atomic64_read(
            &rule_list[index].bytes);

    spin_unlock_bh(&rule_lock);

    if (copy_to_user(
            buffer,
            &info,
            sizeof(info))) {
        return -EFAULT;
    }

    *offset += sizeof(info);

    return sizeof(info);
}


/* ============================================================
 * Device write
 * ============================================================
 */

static ssize_t mfw_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *offset
)
{
    struct mfw_ctl ctl;
    int result = 0;

    if (count != sizeof(ctl))
        return -EINVAL;

    if (copy_from_user(
            &ctl,
            buffer,
            sizeof(ctl))) {
        return -EFAULT;
    }

    spin_lock_bh(&rule_lock);

    switch (ctl.command) {

        case MFW_CMD_ADD:

            result =
                add_rule(
                    &ctl.data.rule);

            break;


        case MFW_CMD_REMOVE:

            result =
                remove_rule(
                    ctl.data.rule_id);

            break;


        case MFW_CMD_FLUSH:

            memset(
                rule_list,
                0,
                sizeof(rule_list));

            rule_count = 0;

            break;


        case MFW_CMD_SET_POLICY:

            if (ctl.data.policy !=
                    MFW_POLICY_ACCEPT &&
                ctl.data.policy !=
                    MFW_POLICY_DROP) {

                result = -EINVAL;

            } else {

                default_policy =
                    ctl.data.policy;
            }

            break;


        case MFW_CMD_GET_POLICY:

            /*
             * GET_POLICY is currently not needed
             * through write(). The CLI can infer
             * the policy through a future ioctl.
             */
            result = -EINVAL;

            break;


        default:

            result = -EINVAL;

            break;
    }

    spin_unlock_bh(&rule_lock);

    if (result < 0)
        return result;

    return count;
}


/* ============================================================
 * File operations
 * ============================================================
 */

static const struct file_operations mfw_fops = {
    .owner = THIS_MODULE,
    .read = mfw_read,
    .write = mfw_write
};


/* ============================================================
 * Module initialization
 * ============================================================
 */

static int __init mfw_init(void)
{
    int result;

    major =
        register_chrdev(
            0,
            DEVICE_NAME,
            &mfw_fops);

    if (major < 0) {
        pr_err(
            "mfw: failed to register character device\n");

        return major;
    }

    mfw_class =
        class_create(CLASS_NAME);

    if (IS_ERR(mfw_class)) {

        result =
            PTR_ERR(mfw_class);

        unregister_chrdev(
            major,
            DEVICE_NAME);

        return result;
    }

    mfw_device =
        device_create(
            mfw_class,
            NULL,
            MKDEV(major, 0),
            NULL,
            DEVICE_NAME);

    if (IS_ERR(mfw_device)) {

        result =
            PTR_ERR(mfw_device);

        class_destroy(mfw_class);

        unregister_chrdev(
            major,
            DEVICE_NAME);

        return result;
    }


    result =
        nf_register_net_hook(
            &init_net,
            &ipv4_input_hook);

    if (result < 0)
        goto fail_ipv4_input;


    result =
        nf_register_net_hook(
            &init_net,
            &ipv4_output_hook);

    if (result < 0)
        goto fail_ipv4_output;


    result =
        nf_register_net_hook(
            &init_net,
            &ipv6_input_hook);

    if (result < 0)
        goto fail_ipv6_input;


    result =
        nf_register_net_hook(
            &init_net,
            &ipv6_output_hook);

    if (result < 0)
        goto fail_ipv6_output;


    pr_info(
        "mfw: MiniFirewall v2 loaded\n");

    pr_info(
        "mfw: IPv4 and IPv6 filtering enabled\n");

    return 0;


fail_ipv6_output:

    nf_unregister_net_hook(
        &init_net,
        &ipv6_input_hook);

fail_ipv6_input:

    nf_unregister_net_hook(
        &init_net,
        &ipv4_output_hook);

fail_ipv4_output:

    nf_unregister_net_hook(
        &init_net,
        &ipv4_input_hook);

fail_ipv4_input:

    device_destroy(
        mfw_class,
        MKDEV(major, 0));

    class_destroy(mfw_class);

    unregister_chrdev(
        major,
        DEVICE_NAME);

    return result;
}


/* ============================================================
 * Module cleanup
 * ============================================================
 */

static void __exit mfw_exit(void)
{
    nf_unregister_net_hook(
        &init_net,
        &ipv6_output_hook);

    nf_unregister_net_hook(
        &init_net,
        &ipv6_input_hook);

    nf_unregister_net_hook(
        &init_net,
        &ipv4_output_hook);

    nf_unregister_net_hook(
        &init_net,
        &ipv4_input_hook);

    device_destroy(
        mfw_class,
        MKDEV(major, 0));

    class_destroy(mfw_class);

    unregister_chrdev(
        major,
        DEVICE_NAME);

    pr_info(
        "mfw: MiniFirewall unloaded\n");
}


module_init(mfw_init);
module_exit(mfw_exit);
