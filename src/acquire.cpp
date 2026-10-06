#include "acquisition.h"
namespace audit {
Result acquire() {
 Result r;
 acquire_suffixes(r);
 acquire_adapters(r);
    r.limitations = {
        // NOLINTNEXTLINE(bugprone-suspicious-missing-comma): intentional literal concatenation.
        "Configuration snapshot only; no DNS queries, hostname resolution, connectivity or server "
        "tests are performed.",
        "API server-list order is preserved; this is not a promise of query selection or priority "
        "across interfaces.",
        "Operationally up does not prove Internet connectivity or DNS reachability.",
        "NRPT, Group Policy beyond the reported SearchList, VPN, enterprise settings and resolver "
        "behavior can alter name resolution.",
        "DoH configuration and transport selection are not audited in version 1.0.0.",
        "SearchList values are raw local configuration, not a reconstructed effective suffix "
        "sequence; suffix devolution and policy precedence are not evaluated.",
        "Registration flags describe adapter configuration, not successful registration or DHCP "
        "server behavior.",
        "Acquisition is not atomic; configuration may change while collecting the snapshot."};
 analyze(r);
 return r;
}
}

