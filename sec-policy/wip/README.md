# wip/ - historical: the network half is done

This directory holds the design record from when the network labelling was still
being worked out. That work is finished and deployed; the live state, the
evidence and the open questions are in `../TRIAGE.md` and in
`../selinux-desktop-system/files/{desktop.system.network.te,ruleset.nftables}`.

Kept rather than deleted because `network-draft.te` records the two options that
were weighed for the mosh ports and why labelling won over a blanket
`unlabeled_t` grant - the same reasoning has since been applied across the whole
ruleset.

## What has changed since this was written

- The `nginx_t -> unlabeled_t` residual on the local gate hop is **fixed**. The
  ruleset re-derives the label for established flows whose conntrack entry
  predates it (`ct direction original`, non-loopback), verified by reading the
  `secctx` back out of conntrack: `http_server_packet_t` where it used to be
  unlabelled, including the sessions that carry the web UI.
- The ruleset also labels DHCP (67/68/546/547), adb and the emulator
  (5037/5554/5555), mDNS for `sysadm_t`, Stremio's `:11471`, the mail ports
  (25/465/587/110/995/143/993), XMPP (5222/5223), and every unclassified
  loopback flow (`local_packet_t`, `oif lo` only).
- The per-tier `*_net_t` domains remain dropped, as recorded below.

## Deploying

The order still matters, and getting it wrong looks like a ruleset bug rather
than an ordering mistake:

    # 1. the policy first - a secmark whose context names a type the running
    #    policy does not define is rejected at load time with "Invalid argument"
    sudo make -C ../selinux-desktop-system merge
    # 2. then the ruleset
    sudo nft -c -f ../selinux-desktop-system/files/ruleset.nftables && \
      sudo nft -f ../selinux-desktop-system/files/ruleset.nftables
    sudo rc-service nftables save

## Safety notes (all still true)

- The ruleset is labelling-only: every chain is `policy accept` and there are no
  drop/reject rules, so loading it cannot block traffic. Its one sharp edge is
  `flush ruleset`, which clears *all* tables - check `nft list tables` first, and
  always run `nft -c` before `nft -f`.
- Conntrack is never flushed: the TCP session carrying the agent's own web UI
  depends on it.
- SELinux is permissive *now*, but see the boot note in `../TRIAGE.md`: OpenRC
  applies `SELINUX=enforcing` from `/etc/selinux/config` at every boot, and the
  current permissive state is a leftover `setenforce 0`. A reboot therefore comes
  up enforcing.

## Still to do

- Confirm mosh matches `mosh_packet_t`. The label and the allow are in place, but
  only real mosh traffic can prove the mapping, and there has been none since.
