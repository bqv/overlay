# wip/ - the network half, in progress

Nothing in this directory is built or loaded. It holds the design record for the
network side while the implementation moves into the packages.

## Status

The packet labelling was already live, and the SELinux side is now started.

| piece | state |
|---|---|
| `ruleset.nftables` secmark labelling (ssh/http/dns/icmp) | **live** - deployed via `/var/lib/nftables/rules-save`, `rc-service nftables` started |
| packet types (`ssh_client_packet_t`, ...) | exist - the `base` module declares 471 of them |
| `mosh_packet_t` + labelling of 60001/60002 | **live** - `../selinux-desktop-system/files/desktop.system.network.te`, loaded, and deployed to the ruleset |
| `staff_t -> mosh_packet_t { send recv }` | implemented, same module |
| `stremio_server_t -> ssh_client_packet_t { send recv }` | implemented, same module |
| per-tier `*_net_t` domains | **not used** - the packet-label approach below made them unnecessary; the stub they lived in was promoted into the network module and they were dropped |

## The decision

The captures showed 59 `packet` denials: 53 send + 16 recv from `staff_t` to
`unlabeled_t` (mosh, UDP 60001/60002), and 2+2 from `stremio_server_t` to
`ssh_client_packet_t`.

The cause of the mosh ones: `secmapping_out` only labelled ports 22, 53, 80 and
443, so every other flow arrived as `unlabeled_t`. Two ways out - allow
`unlabeled_t` wholesale for `staff_t`, or label mosh's ports too. **The ports
are being labelled**, so the secmark keeps covering the traffic instead of the
policy granting a blanket exception. `network-draft.te` records both options
and the evidence; the module implements the second.

## Deploying

Both halves are live. The order matters, and getting it wrong looks like a
ruleset bug rather than an ordering mistake:

    # 1. the policy first - a secmark whose context names a type the running
    #    policy does not define is rejected at load time with "Invalid argument"
    sudo make -C ../selinux-desktop-system merge
    # 2. then the ruleset
    sudo nft -f ../selinux-desktop-system/files/ruleset.nftables
    sudo rc-service nftables save

## Still to do

1. **Re-capture with mosh running** and confirm the `staff_t -> unlabeled_t`
   denials are gone and the traffic now matches `mosh_packet_t`. This needs a
   live mosh session - there is no way to prove it without the traffic.
4. If the per-tier network separation is still wanted later, the `*_net_t`
   domains are the way - but they need roles and entrypoints, and the packet
   labels already give per-flow control without them.
