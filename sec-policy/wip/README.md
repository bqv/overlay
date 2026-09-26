# wip/ - the next phase, not an archive

Nothing here is in a `MODS`/`POLICY_FILES` list, so nothing here is built or
loaded. It is kept because it is the start of the **network half** of this
policy, which is the point of the exercise. Do not treat this directory as a
graveyard.

## What is here

`desktop.system.network.te` declares three per-tier network domains -
`sysadm_net_t`, `staff_net_t`, `user_net_t` - and gives each
`corenet_sendrecv_unlabeled_packets()`. Nothing maps a domain to these types,
none of them has a role or an entrypoint, and no file context uses them, so
they are inert. They are the intended home for per-tier network confinement,
mirroring the per-tier file separation that was started in
`desktop.system.users` (see the top-level README).

## What is NOT here, because it is already live

`../selinux-desktop-system/files/ruleset.nftables` is **deployed**, not
inert. It is the `secmark` ruleset that labels packets by protocol/port and
direction:

    secmark ssh_server -> system_u:object_r:ssh_server_packet_t:s0
    secmark http_client -> ...http_client_packet_t...   (and dns, icmp)

`rc-service nftables` is started, and the deployed copy lives in
`/var/lib/nftables/rules-save` (`NFTABLES_SAVE` in `/etc/conf.d/nftables`);
there is no `/etc/nftables.conf` or `/etc/nftables.d/`. The packet types
themselves exist in the policy - they come from the `base` module
(`include/kernel/corenetwork.if`).

Deploying the overlay copy, after editing it:

    sudo nft -f selinux-desktop-system/files/ruleset.nftables
    sudo rc-service nftables save

### Known drift (overlay vs deployed)

The overlay copy is one revision **ahead**: it has four `iif lo` rules that
label localhost SSH traffic, and the deployed `/var/lib/nftables/rules-save`
has none. Everything else matches modulo formatting. So the overlay is the
source and the deployment is behind - running the two commands above closes
the gap.

## The live evidence

The labelling is already producing real SELinux packet denials - 59 of them
across `../captures/`. Mapped out:

| count | source domain | target packet type | what it is |
|---|---|---|---|
| 53 | `staff_t` | `unlabeled_t` | mosh UDP 60001/60002 to 62.210.213.30 |
| 2 | `staff_t` | `unlabeled_t` | same (permissive) |
| 4 | `stremio_server_t` | `ssh_client_packet_t` | Stremio connecting outward to :22 |

Two distinct deficits, and only one of them is a missing allow:

1. **`unlabeled_t` is the common case, not the exception.** The secmark maps
   cover only ports 22, 53, 80 and 443, so every other flow - mosh on 60001/2,
   and anything else - is unlabelled and hits `unlabeled_t`. Either the maps
   grow (mosh's ports) or the policy allows unlabelled packets wholesale. The
   draft for the latter is already written and commented out in
   `../selinux-desktop-home/files/desktop.home.te`:
   `#corenet_sendrecv_unlabeled_packets(staff_t) # MainThread?`.
   This is a design decision, not a mechanical one - pick one.
2. **`stremio_server_t` -> `ssh_client_packet_t`** needs `{ send recv }`.
   Currently masked because `stremio_server_t` is in a permissive domain
   (`semodule -l` shows `permissive_stremio_server_t`).

## `network-draft.te`

The concrete allows the 59 denials call for, with the evidence and the
trade-offs, are drafted in `network-draft.te` in this directory. Not installed,
not built - it is a review artifact. It also notes that `staff_t` itself is
currently in a permissive domain, so most of these denials are logged rather
than enforced, and the packet evidence should be re-read once that changes.

## Wiring order

1. Decide the `unlabeled_t` question above; it affects every domain, not just
   mosh.
2. Add the per-domain `packet` allows for the labels each domain legitimately
   sends/receives (start from the captures, as usual).
3. Give the three `*_net_t` domains roles and entrypoints, or delete them and
   do per-domain packet allows directly - the middle layer is optional and so
   far unused.
4. Deploy the ruleset from the overlay and re-capture to confirm the denials
   are gone for the traffic that should be allowed and still present for the
   traffic that should not.
