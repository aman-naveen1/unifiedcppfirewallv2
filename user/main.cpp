#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../include/mfw_protocol.h"


static void print_usage()
{
    std::cout
        << "\n"
        << "MiniFirewall v2\n"
        << "\n"
        << "Usage:\n"
        << "  mfw add [options]\n"
        << "  mfw remove --id ID\n"
        << "  mfw list\n"
        << "  mfw flush\n"
        << "  mfw policy accept\n"
        << "  mfw policy drop\n"
        << "\n"
        << "Add rule options:\n"
        << "  -i, --in                 Incoming traffic\n"
        << "  -o, --out                Outgoing traffic\n"
        << "  -s, --source CIDR        Source address\n"
        << "  -d, --destination CIDR   Destination address\n"
        << "  -p, --protocol PROTO     tcp, udp, icmp, icmpv6, any\n"
        << "      --sport PORT         Source port\n"
        << "      --dport PORT         Destination port\n"
        << "  -a, --action ACTION      allow or drop\n"
        << "      --priority NUMBER    Rule priority\n"
        << "\n"
        << "Examples:\n"
        << "  mfw add --in "
        << "--source 192.168.1.0/24 "
        << "--protocol tcp "
        << "--dport 22 "
        << "--action drop\n"
        << "\n"
        << "  mfw add --out "
        << "--destination 8.8.8.8/32 "
        << "--protocol udp "
        << "--dport 53 "
        << "--action allow\n"
        << "\n"
        << "  mfw add --in "
        << "--source 2001:db8::/64 "
        << "--protocol tcp "
        << "--dport 443 "
        << "--action allow\n"
        << "\n";
}


/* ============================================================
 * Parse integer
 * ============================================================
 */

static bool parse_uint(
    const char* text,
    uint32_t min,
    uint32_t max,
    uint32_t& value
)
{
    char* end = nullptr;

    unsigned long result =
        std::strtoul(
            text,
            &end,
            10);

    if (end == text ||
        *end != '\0' ||
        result < min ||
        result > max) {

        return false;
    }

    value =
        static_cast<uint32_t>(result);

    return true;
}


/* ============================================================
 * Parse CIDR
 * ============================================================
 */

static bool parse_cidr(
    const std::string& text,
    mfw_addr& address
)
{
    std::size_t slash =
        text.find('/');

    if (slash == std::string::npos)
        return false;

    std::string ip =
        text.substr(
            0,
            slash);

    std::string prefix_text =
        text.substr(
            slash + 1);

    uint32_t prefix;

    if (!parse_uint(
            prefix_text.c_str(),
            0,
            128,
            prefix)) {
        return false;
    }

    in_addr ipv4;

    if (inet_pton(
            AF_INET,
            ip.c_str(),
            &ipv4) == 1) {

        if (prefix > 32)
            return false;

        std::memset(
            &address,
            0,
            sizeof(address));

        address.family =
            MFW_AF_INET;

        address.prefix =
            static_cast<uint8_t>(prefix);

        address.addr.ipv4 =
            ipv4.s_addr;

        return true;
    }


    in6_addr ipv6;

    if (inet_pton(
            AF_INET6,
            ip.c_str(),
            &ipv6) == 1) {

        std::memset(
            &address,
            0,
            sizeof(address));

        address.family =
            MFW_AF_INET6;

        address.prefix =
            static_cast<uint8_t>(prefix);

        std::memcpy(
            address.addr.ipv6,
            &ipv6,
            16);

        return true;
    }

    return false;
}


/* ============================================================
 * Parse protocol
 * ============================================================
 */

static bool parse_protocol(
    const std::string& text,
    uint8_t& protocol
)
{
    if (text == "any") {
        protocol = MFW_PROTO_ANY;
        return true;
    }

    if (text == "tcp") {
        protocol = MFW_PROTO_TCP;
        return true;
    }

    if (text == "udp") {
        protocol = MFW_PROTO_UDP;
        return true;
    }

    if (text == "icmp") {
        protocol = MFW_PROTO_ICMP;
        return true;
    }

    if (text == "icmpv6") {
        protocol = MFW_PROTO_ICMPV6;
        return true;
    }

    uint32_t number;

    if (parse_uint(
            text.c_str(),
            0,
            255,
            number)) {

        protocol =
            static_cast<uint8_t>(number);

        return true;
    }

    return false;
}


/* ============================================================
 * Parse action
 * ============================================================
 */

static bool parse_action(
    const std::string& text,
    uint8_t& action
)
{
    if (text == "allow") {

        action =
            MFW_ACTION_ALLOW;

        return true;
    }

    if (text == "drop") {

        action =
            MFW_ACTION_DROP;

        return true;
    }

    return false;
}


/* ============================================================
 * Write command to kernel
 * ============================================================
 */

static bool send_command(
    const mfw_ctl& command
)
{
    int fd =
        open(
            MFW_DEVICE,
            O_WRONLY);

    if (fd < 0) {

        std::cerr
            << "Error: cannot open "
            << MFW_DEVICE
            << ". Are you running as root and is the module loaded?\n";

        return false;
    }

    ssize_t written =
        write(
            fd,
            &command,
            sizeof(command));

    close(fd);

    if (written !=
        static_cast<ssize_t>(
            sizeof(command))) {

        std::cerr
            << "Error: kernel rejected command";

        if (written < 0)
            std::cerr
                << " (errno="
                << errno
                << ")";

        std::cerr << "\n";

        return false;
    }

    return true;
}


/* ============================================================
 * Convert address to string
 * ============================================================
 */

static std::string address_to_string(
    const mfw_addr& address
)
{
    char buffer[INET6_ADDRSTRLEN];

    std::memset(
        buffer,
        0,
        sizeof(buffer));

    if (address.family ==
        MFW_AF_INET) {

        in_addr addr;

        addr.s_addr =
            address.addr.ipv4;

        if (inet_ntop(
                AF_INET,
                &addr,
                buffer,
                sizeof(buffer))) {

            return std::string(buffer)
                + "/"
                + std::to_string(
                    address.prefix);
        }
    }


    if (address.family ==
        MFW_AF_INET6) {

        in6_addr addr;

        std::memcpy(
            &addr,
            address.addr.ipv6,
            16);

        if (inet_ntop(
                AF_INET6,
                &addr,
                buffer,
                sizeof(buffer))) {

            return std::string(buffer)
                + "/"
                + std::to_string(
                    address.prefix);
        }
    }

    return "any";
}


/* ============================================================
 * Protocol name
 * ============================================================
 */

static std::string protocol_to_string(
    uint8_t protocol
)
{
    switch (protocol) {

        case MFW_PROTO_TCP:
            return "TCP";

        case MFW_PROTO_UDP:
            return "UDP";

        case MFW_PROTO_ICMP:
            return "ICMP";

        case MFW_PROTO_ICMPV6:
            return "ICMPv6";

        case MFW_PROTO_ANY:
            return "ANY";

        default:
            return std::to_string(
                protocol);
    }
}


/* ============================================================
 * Action name
 * ============================================================
 */

static std::string action_to_string(
    uint8_t action
)
{
    if (action == MFW_ACTION_ALLOW)
        return "ALLOW";

    return "DROP";
}


/* ============================================================
 * List rules
 * ============================================================
 */

static bool list_rules()
{
    int fd =
        open(
            MFW_DEVICE,
            O_RDONLY);

    if (fd < 0) {

        std::cerr
            << "Error: cannot open "
            << MFW_DEVICE
            << "\n";

        return false;
    }

    std::cout
        << "\n"
        << std::left
        << std::setw(5)
        << "ID"
        << std::setw(9)
        << "PRI"
        << std::setw(7)
        << "DIR"
        << std::setw(8)
        << "ACTION"
        << std::setw(9)
        << "PROTO"
        << std::setw(28)
        << "SOURCE"
        << std::setw(28)
        << "DESTINATION"
        << std::setw(8)
        << "SPORT"
        << std::setw(8)
        << "DPORT"
        << std::setw(12)
        << "PACKETS"
        << "BYTES\n";

    std::cout
        << std::string(
            145,
            '-')
        << "\n";


    while (true) {

        mfw_rule_info info{};

        ssize_t received =
            read(
                fd,
                &info,
                sizeof(info));

        if (received == 0)
            break;

        if (received < 0) {

            std::cerr
                << "Error reading rules\n";

            close(fd);

            return false;
        }

        if (received !=
            static_cast<ssize_t>(
                sizeof(info))) {

            std::cerr
                << "Error: incomplete rule received\n";

            close(fd);

            return false;
        }


        std::cout
            << std::left
            << std::setw(5)
            << info.rule.id

            << std::setw(9)
            << info.rule.priority

            << std::setw(7)
            << (info.rule.direction ==
                    MFW_DIR_IN
                    ? "IN"
                    : "OUT")

            << std::setw(8)
            << action_to_string(
                info.rule.action)

            << std::setw(9)
            << protocol_to_string(
                info.rule.protocol)

            << std::setw(28)
            << address_to_string(
                info.rule.source)

            << std::setw(28)
            << address_to_string(
                info.rule.destination)

            << std::setw(8)
            << info.rule.source_port

            << std::setw(8)
            << info.rule.destination_port

            << std::setw(12)
            << info.stats.packets

            << info.stats.bytes

            << "\n";
    }

    close(fd);

    std::cout << "\n";

    return true;
}


/* ============================================================
 * Main
 * ============================================================
 */

int main(
    int argc,
    char* argv[]
)
{
    if (argc < 2) {

        print_usage();

        return EXIT_FAILURE;
    }


    std::string command =
        argv[1];


    /* --------------------------------------------------------
     * LIST
     * --------------------------------------------------------
     */

    if (command == "list") {

        return list_rules()
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
    }


    /* --------------------------------------------------------
     * FLUSH
     * --------------------------------------------------------
     */

    if (command == "flush") {

        mfw_ctl ctl{};

        ctl.command =
            MFW_CMD_FLUSH;

        return send_command(ctl)
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
    }


    /* --------------------------------------------------------
     * POLICY
     * --------------------------------------------------------
     */

    if (command == "policy") {

        if (argc != 3) {

            std::cerr
                << "Usage: mfw policy accept|drop\n";

            return EXIT_FAILURE;
        }

        mfw_ctl ctl{};

        ctl.command =
            MFW_CMD_SET_POLICY;

        if (std::string(argv[2]) ==
            "accept") {

            ctl.data.policy =
                MFW_POLICY_ACCEPT;

        } else if (
            std::string(argv[2]) ==
            "drop") {

            ctl.data.policy =
                MFW_POLICY_DROP;

        } else {

            std::cerr
                << "Invalid policy\n";

            return EXIT_FAILURE;
        }

        return send_command(ctl)
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
    }


    /* --------------------------------------------------------
     * REMOVE
     * --------------------------------------------------------
     */

    if (command == "remove") {

        if (argc != 4 ||
            std::string(argv[2]) != "--id") {

            std::cerr
                << "Usage: mfw remove --id ID\n";

            return EXIT_FAILURE;
        }

        uint32_t id;

        if (!parse_uint(
                argv[3],
                1,
                MFW_MAX_RULES,
                id)) {

            std::cerr
                << "Invalid rule ID\n";

            return EXIT_FAILURE;
        }

        mfw_ctl ctl{};

        ctl.command =
            MFW_CMD_REMOVE;

        ctl.data.rule_id =
            id;

        return send_command(ctl)
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
    }


    /* --------------------------------------------------------
     * ADD
     * --------------------------------------------------------
     */

    if (command != "add") {

        print_usage();

        return EXIT_FAILURE;
    }


    mfw_rule rule{};

    rule.direction = 0;

    rule.action =
        MFW_ACTION_DROP;

    rule.protocol =
        MFW_PROTO_ANY;

    rule.priority = 100;

    rule.source.family =
        MFW_AF_ANY;

    rule.destination.family =
        MFW_AF_ANY;


    static struct option options[] = {

        {"in",
         no_argument,
         nullptr,
         'i'},

        {"out",
         no_argument,
         nullptr,
         'o'},

        {"source",
         required_argument,
         nullptr,
         's'},

        {"destination",
         required_argument,
         nullptr,
         'd'},

        {"protocol",
         required_argument,
         nullptr,
         'p'},

        {"sport",
         required_argument,
         nullptr,
         1000},

        {"dport",
         required_argument,
         nullptr,
         1001},

        {"action",
         required_argument,
         nullptr,
         'a'},

        {"priority",
         required_argument,
         nullptr,
         1002},

        {nullptr,
         0,
         nullptr,
         0}
    };


    optind = 2;

    while (true) {

        int option =
            getopt_long(
                argc,
                argv,
                "ios:d:p:a:",
                options,
                nullptr);

        if (option == -1)
            break;


        switch (option) {

            case 'i':

                if (rule.direction != 0) {

                    std::cerr
                        << "Specify only --in or --out\n";

                    return EXIT_FAILURE;
                }

                rule.direction =
                    MFW_DIR_IN;

                break;


            case 'o':

                if (rule.direction != 0) {

                    std::cerr
                        << "Specify only --in or --out\n";

                    return EXIT_FAILURE;
                }

                rule.direction =
                    MFW_DIR_OUT;

                break;


            case 's':

                if (!parse_cidr(
                        optarg,
                        rule.source)) {

                    std::cerr
                        << "Invalid source CIDR: "
                        << optarg
                        << "\n";

                    return EXIT_FAILURE;
                }

                break;


            case 'd':

                if (!parse_cidr(
                        optarg,
                        rule.destination)) {

                    std::cerr
                        << "Invalid destination CIDR: "
                        << optarg
                        << "\n";

                    return EXIT_FAILURE;
                }

                break;


            case 'p':

                if (!parse_protocol(
                        optarg,
                        rule.protocol)) {

                    std::cerr
                        << "Invalid protocol\n";

                    return EXIT_FAILURE;
                }

                break;


            case 'a':

                if (!parse_action(
                        optarg,
                        rule.action)) {

                    std::cerr
                        << "Action must be allow or drop\n";

                    return EXIT_FAILURE;
                }

                break;


            case 1000: {

                uint32_t port;

                if (!parse_uint(
                        optarg,
                        1,
                        65535,
                        port)) {

                    std::cerr
                        << "Invalid source port\n";

                    return EXIT_FAILURE;
                }

                rule.source_port =
                    static_cast<uint16_t>(
                        port);

                break;
            }


            case 1001: {

                uint32_t port;

                if (!parse_uint(
                        optarg,
                        1,
                        65535,
                        port)) {

                    std::cerr
                        << "Invalid destination port\n";

                    return EXIT_FAILURE;
                }

                rule.destination_port =
                    static_cast<uint16_t>(
                        port);

                break;
            }


            case 1002: {

                uint32_t priority;

                if (!parse_uint(
                        optarg,
                        0,
                        UINT32_MAX,
                        priority)) {

                    std::cerr
                        << "Invalid priority\n";

                    return EXIT_FAILURE;
                }

                rule.priority =
                    priority;

                break;
            }


            default:

                print_usage();

                return EXIT_FAILURE;
        }
    }


    if (rule.direction == 0) {

        std::cerr
            << "You must specify --in or --out\n";

        return EXIT_FAILURE;
    }


    if (rule.source.family != MFW_AF_ANY &&
        rule.destination.family != MFW_AF_ANY &&
        rule.source.family !=
            rule.destination.family) {

        std::cerr
            << "Source and destination "
            << "address families must match\n";

        return EXIT_FAILURE;
    }


    if ((rule.source_port != 0 ||
         rule.destination_port != 0) &&
        rule.protocol != MFW_PROTO_TCP &&
        rule.protocol != MFW_PROTO_UDP) {

        std::cerr
            << "Ports can only be used with TCP or UDP\n";

        return EXIT_FAILURE;
    }


    mfw_ctl ctl{};

    ctl.command =
        MFW_CMD_ADD;

    ctl.data.rule =
        rule;


    if (!send_command(ctl))
        return EXIT_FAILURE;


    std::cout
        << "Rule added successfully.\n";

    return EXIT_SUCCESS;
}
