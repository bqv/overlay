# Denial triage ledger

Target: this box switching to SELinux **enforcing**, so every AVC is a work
item. This is the running inventory - update it whenever the policy is merged,
because captures go stale the moment a module is reloaded.

## Method

    sudo ./aud "10 minutes ago" <name>        # -> captures/<date>-<name>.audit

Attribute by `comm=` before reading anything, and drop self-inflicted noise
first. One capture held 38,474 AVCs of which **61% was `grep`/`python3` walking
`/var/db/pkg`** - the instrumentation, not the box. The real count was ~1,100.

Decide each pattern by what it does under enforcing:

- legitimate -> grant (refpolicy interface first, raw allow as fallback);
- genuinely unwanted -> leave denied, and say what breaks;
- `dontaudit` only where nothing functionally fails;
- anything that cannot be resolved gets recorded as such, not guessed at.

## Settled

| pattern | decision | mechanism |
|---|---|---|
| `staff_t -> <domain>:dir/file/lnk_file { read }` - htop/nvtop walking `/proc` | granted | `domain_read_all_domains_state(staff_t)`, refpolicy's interface for it; ~5,000 denials in one capture |
| `staff_t -> <domain>:{tcp,udp,unix_*,netlink_*}_socket { getattr }` - nvtop following `/proc/<pid>/fd` | granted | raw allows naming the socket classes: refpolicy has no interface for these (`domain_getattr_all_domains` covers only `process`) and `getattr` is read-only metadata |
| `staff_t -> self:anon_inode { getattr }` | granted | `allow staff_t self:anon_inode getattr;` |
| `allow staff_t shadow_t:file { getattr open read }` | **impossible - removed** | the base policy carries `neverallow authlogin_typeattr_1 shadow_t:file read` and `staff_t` is a user domain. That one line made the home package unlinkable, so **it had never been installed** - the loaded module had no `shadow_t` rule at all. Password checks go through PAM/chkpwd_t |
| `nginx_t -> http_cache_port_t:tcp_socket { name_connect }` (nginx -> the local gate on :8080) | granted | `corenet_tcp_connect_http_cache_port(nginx_t)` - **under enforcing the web UI would stop answering without this** |
| `staff_t -> node_t:tcp_socket { node_bind }` (adb) | granted | `corenet_tcp_bind_generic_node(staff_t)` |
| `staff_t -> fuse_device_t:chr_file { read write }` (fuse_worker) | granted | `storage_rw_fuse(staff_t)` |
| `staff_bubblewrap_t -> {proc,debugfs,configfs,pstore,efivarfs,bpf,devpts,tracefs,binfmt_misc}_t:filesystem { remount }` (~200/capture) | granted | `fs_remount_all_fs(staff_bubblewrap_t)` - without it the sandbox cannot be built under enforcing, and this session runs inside bwrap |
| `staff_bubblewrap_t -> ptmx_t:chr_file { read write }` | granted | `term_use_ptmx(staff_bubblewrap_t)` |
| `staff_bubblewrap_t -> xdg_data_t:lnk_file { read }`, `self:udp_socket { read }` | granted | raw allows |
| `staff_t -> staff_bubblewrap_t:process { setsched }`, `staff_t -> self:process { ptrace }` | granted | raw allows (the harness scheduling and inspecting its own children) |
| `staff_t -> domain:anon_inode { getattr }` | granted | widened from `self:` - nvtop stats other domains' anon_inodes too |
| `semanage_t` relabelling the policy store (`setsebool -P` in `pkg_postinst`) | **fixed** | I first recorded this as unfixable-by-constraint and was wrong. The UBAC constraint is `(or (eq u1 u2) (eq t1 can_change_object_identity))`; `eq u1 u2` can never hold (`staff_u` subject, `system_u` store files) but the *type membership* branch can be satisfied: `attribute can_change_object_identity;` in the require plus `typeattribute semanage_t can_change_object_identity;`. No neverallow guards it, it links, and `setsebool -P` now produces **zero** relabelto denials - so `make merge` is clean under enforcing |
| `staff_t -> self:io_uring { allowed }` (the harness) | granted | `class io_uring allowed;` + `allow staff_t self:io_uring allowed;`. Worth knowing: the kernel denies two different io_uring perms and they behave differently - `allowed` is in the policy's class table and grants fine, `getattr` is not and cannot be (see Outstanding) |
| `staff_t -> unreserved_port_t:tcp_socket { name_bind }` (java, protonmail-bridge) | granted | `corenet_tcp_bind_all_unreserved_ports(staff_t)` - it expands against the `unreserved_port_type` attribute, not the `unreserved_port_t` type, which is worth remembering when verifying |
| `dhcpc_script_t -> init_runtime_t:dir { search }` | granted | raw allow; refpolicy has no search interface for the init runtime dir |
| `staff_git_t -> portage_ebuild_t:{dir,file}` (git, 35/capture), `staff_screen_t -> portage_ebuild_t:dir { search }` (tmux, 6) | granted | `portage_read_ebuild(staff_git_t)` plus a raw search allow for tmux. The overlay lives under `/var/db/repos`, whose tree is labelled `portage_ebuild_t`, and refpolicy only expects portage tools there - so ordinary tooling working in that tree needs traversal |
| `sysadm_t -> portage_ebuild_t:file { execute, execute_no_trans, read, open }` | granted | `portage_read_ebuild(sysadm_t)` + `can_exec(sysadm_t, portage_ebuild_t)`, so `make -C <pkg> compile/merge` runs an ebuild under enforcing |
| `staff_bubblewrap_t -> proc_psi_t:dir { search }` | granted | `kernel_read_psi(staff_bubblewrap_t)` - verified 0 denials afterwards |
| network: mosh 60001/2, nginx :80, the local :8080 gate hop, mDNS 5353, ssh/http/dns/icmp | granted | secmark labelling + packet-type allows; see `wip/README.md` |

## Outstanding

| pattern | what breaks under enforcing | plan |
|---|---|---|
| `semanage_t` relabelling the policy store (`setsebool -P` in the ebuild's `pkg_postinst`) | **blocked by a constraint, not by a missing allow** | the base policy carries `(constrain (file (create relabelfrom relabelto)) (or (eq u1 u2) (eq t1 can_change_object_identity)))`, and `can_change_object_identity` contains **only `kernel_t`**. The subject is `staff_u` (sudo keeps the SELinux user) and the store files are `system_u`, so `u1 eq u2` fails. Constraints sit above allows: `seutil_manage_module_store(semanage_t)` and `seutil_relabelto_bin_policy(semanage_t)` are now in the policy and the denials continue regardless. `setsebool` still exits 0 here, but permissive mode cannot tell us whether enforcing would make it fail. Robust fix is to stop re-applying booleans in `pkg_postinst` on every merge |
| `staff_t -> self:io_uring { allowed }` (the harness, and nvtop on `getattr`) | io_uring fds unusable/stat-able depending on the perm | **blocked**: checkmodule's class table has io_uring perms the policy's does not, so declaring and allowing makes semodule fail with `Failed to resolve permission getattr`. Kernel-vs-policy class-table mismatch, not a policy bug - revisit after a libsepol/base-policy rebuild |
| `mozilla_t -> cgroup_t:file { getattr }` (WebContent reading `/sys/fs/cgroup/*/cpu.max`) | the browser cannot read its cgroup | grant via the cgroup-getattr interface |
| `staff_t -> policy_config_t:dir { getattr }` on `/etc/selinux/mcs/policy` (from bash) | a shell cannot stat the policy directory | identify the caller, then grant |
| `staff_t -> staff_t:process { ptrace }` (`node-MainThread`, 21/capture) | the harness could not ptrace | find what asks for it |
| `staff_t -> node_t:tcp_socket { node_bind }` (`adb`, 19/capture) | adb cannot bind its node port | legitimate for adb -> grant |
| `staff_bubblewrap_t -> {proc,debugfs,configfs,pstore}_t:filesystem { getattr }` | statfs on those pseudo-filesystems fails | `kernel_getattr_*` interfaces |
| `semanage_t -> semanage_store_t:{file,dir}`, `policy_config_t:file`, `file_context_t:file` | `semanage` cannot write the policy store | legitimate for the admin tool -> grant |

| `semanage_t -> semanage_store_t:{file,dir}`, `policy_config_t:file`, `file_context_t:file`, `selinux_config_t:file` { relabelto }, `tracefs_t:filesystem { getattr }` - from `setsebool`/`semodule` | **the ebuild's own `pkg_postinst` would fail**: `setsebool -P` could not relabel the policy store, so `make merge` breaks under enforcing | grant `semanage_t` the relabelto it needs, or drop the `setsebool` calls from the ebuild |
| `sysadm_t -> portage_ebuild_t:file { execute, execute_no_trans, read, open }`, `staff_t -> portage_ebuild_t:file { read, open }` | running an ebuild fails | legitimate for portage work -> grant |
| `staff_bubblewrap_t -> proc_psi_t:dir { search }` | pressure-stall info unreadable in the sandbox | grant |
| `staff_git_t -> {user_tmpfs_t:dir search, ptmx_t:chr_file rw, portage_tmp_t:file rw, staff_t:unix_stream_socket}` and `staff_t -> staff_git_t:process { nnp_transition nosuid_transition }` | git via the staff_git_t wrapper | staff_git_t is in the permissive list; triage when it comes off |
| `nginx_t -> unlabeled_t:packet { send recv }` on 127.0.0.1:33278 <-> :8080 | nginx cannot talk to the gate | the legacy conntrack entry that predates the 8080 mapping. Clearing it needs a conntrack flush, which is **not** done - it would reset the session. Self-heals when the connection recycles |

## Settled this round

| pattern | decision |
|---|---|
| `staff_git_t -> user_bin_t` (~40 denials per git run) and `ptmx_t:chr_file` | **fixed** - verified: a real `git status` in `~/bin/<repo>` now produces **0** denials, down from ~40. Mechanism: `userdom_manage_user_bin(staff_git_t)` + `term_use_ptmx(staff_git_t)`, plus one precise `allow staff_git_t user_bin_t:file map;` because git mmaps its index and no interface grants `map` on `user_bin_t` (`userdom_map_user_home_content_files` covers `user_home_t` only; the `map_all` variant would grant it on every home content type) |

### A class worth knowing: per-role application domains get no home access

`staff_git_t` was not a one-off. refpolicy's `staff` module declares per-role
application domains inside optional blocks, and they receive the *application's*
own access (`git_exec_t`, `git_home_t`, ...) but nothing for the user's home.
Of the 16 `staff_*_t` types, these have **zero** home/bin rules:

    staff_cockpit_tmpfs_t   (a tmpfs file type, not a domain)
    staff_dbusd_tmpfs_t     (likewise)
    staff_feedbackd_t
    staff_git_t             <- fixed this round
    staff_gkeyringd_t       <- implicated: `staff_gkeyringd_t -> portage_tmp_t`
    staff_userhelper_t

So under enforcing, any app that *transitions* into a per-role domain loses the
user's files. `staff_git_t` was simply the one that got exercised. The other
three process domains are worth the same treatment as they turn up.

| pattern | decision |
|---|---|
| `mozilla_t -> cgroup_t:file { getattr read open }` on `/sys/fs/cgroup/*/cpu.max` | granted: `fs_read_cgroup_files(mozilla_t)` - the browser reads its own cgroup |
| `staff_t -> portage_ebuild_t:file { read open }` | granted: `portage_read_ebuild(staff_t)`. The overlay lives under `/var/db/repos`, so *reading* the policy source as the session user is denied otherwise - without this the policy could not be maintained as staff_t under enforcing |
| `mozilla_t -> portage_tmp_t:file` on `/usr/lib/locale/locale-archive` | **not a policy problem**: the file was mislabelled `portage_tmp_t` (a glibc rebuild's leftover). `matchpathcon` says `locale_t`, and `restorecon` fixed it. Worth remembering that a denial can be the *label* being wrong rather than the policy being incomplete |

## The nginx :80 packet denials - transient, not a gap

Occasional `nginx_t -> unlabeled_t:packet { send recv }` on new connections.
Investigated: the *stored* conntrack entry for the same flow carries
`secctx=system_u:object_r:http_server_packet_t:s0`, real client connections
(`192.168.1.100 -> :80`) show the correct `http_server_packet_t`, and nginx's
allow for it is in the policy. Three fresh connections produced two AVCs, so it
is a setup-time race on the first packet, not per-connection and not a labelling
gap. Under enforcing it would drop that packet and TCP would retransmit.
The likely fix is the ruleset's hook priority - the input chain sits at `-225`,
the same priority SELinux uses - but that is the ruleset's design and a change
to nftables, so it is recorded rather than done.

## Outstanding (new this round)

| pattern | what breaks under enforcing | plan |
|---|---|---|
| `staff_git_t -> user_bin_t:{dir,file}` (62 in one 60s window, `git`) | git cannot work in `~/bin` | the largest new item; grant via the userdom interface |
| `gpg_t -> portage_tmp_t:file`, `gpg_t -> user_home_t:{file,dir}` (`gpg2`) | gpg cannot sign (git commits) | legitimate - grant |
| `staff_t -> self:process { execmem }` (`java`) | the JIT runtime cannot allocate executable memory | refpolicy's `allow_execmem` boolean is the designed switch, and `setsebool -P` works now - but it is a W^X relaxation, so it is a deliberate choice, not a silent grant |
| `staff_t -> xdg_config_t:file { execute }` (`rc-service`) | an openrc user service cannot start | identify the script, then grant |
| `staff_gkeyringd_t -> portage_tmp_t:file` (`gnome-keyring-d`), `staff_bubblewrap_t -> user_tmp_t:file` (`steamwebhelper`), `mozilla_t -> cgroup_t:file` | keyring / Steam / the browser lose that access | triage individually - they look like stray reads rather than missing classes |

## UBAC is active, and the `-ubac` flag does not turn it off

The `setsebool` block was a UBAC constraint, and `refpolicy/policy/constraints`
wraps those in `ifdef(enable_ubac)`, which comes from `build.conf`'s `UBAC = y`.
So UBAC is on in the running policy. But `/etc/portage/package.use/selinux-base`
sets `sec-policy/selinux-base -ubac`, and neither installed sec-policy package
records `ubac` in its USE at all.

The flag is on the wrong package. `sec-policy/selinux-base` is the one with a
`ubac` USE flag (it rewrites `build.conf`), but the package that actually
*compiles the base policy* is `sec-policy/selinux-base-policy`, which has no such
flag - so it always builds with refpolicy's default `UBAC = y`. Consequence:
UBAC is in force whatever that flag says, which is why the constraint had to be
satisfied rather than configured away. Turning it off needs a build patch, not a
USE flag.

This matters for triage beyond that one denial: under UBAC the **SELinux user**
component of a label is checked (`u1 == u2`), not just the type.

## The overlay's labels are inconsistent

A census of `/var/db/repos/local`:

    1475  system_u:object_r:portage_ebuild_t
     101  staff_u:object_r:portage_ebuild_t
       1  staff_u:object_r:user_home_t
       1  root:object_r:etc_runtime_t

Everything should be `system_u:object_r:portage_ebuild_t` (matchpathcon agrees).
The `etc_runtime_t` one is a policy source file that a denied `staff_git_t` could
not even stat, and under active UBAC the mixed SELinux users are checked too.
`restorecon -R` would normalise all of it - **not done**: it rewrites the user
component of the very files this workflow edits, so it needs the operator's
decision rather than mine.

## Enforcement readiness: the critical paths

The noise question ("what is denied?") is nearly settled, so the useful question
becomes the lockout one: **is any service whose failure would cut off access
being denied anything?** Scanning for denials whose *subject* is a critical
service gives a short list:

| subject | denials | disposition |
|---|---|---|
| `staff_sudo_t` | inherited-fd perms on `chkpwd_t`/`sysadm_t` (~70), `proc_t:filesystem getattr` (25) | the fd perms are the class this package already dontaudits elsewhere - informational, transition not blocked - so `dontaudit`; the statfs gets `kernel_getattr_proc()`. sudo keeps working |
| `sshd_t` | `initrc_state_t` reads (2 each), `var_run_t:file read` (1) | **the lockout-relevant pair.** This box is reached over SSH (`branch pts/2 (192.168.1.100)` is logged in right now), so these are granted: `init_read_script_status_files(sshd_t)` and a read on `var_run_t` |
| `systemd_logind_t` | `cgroup_t:file watch` (1) | `fs_watch_cgroup_files()` |
| everything else | none | sshd, xdm, dbusd, logind, pipewire, wireplumber, init, auditd, getty have no denials of their own |

Verified live: sshd listening on :22 with a session connected, X sockets up,
9 dbus processes, pipewire+wireplumber running. **No critical service is denied
anything it needs.**

## Tooling note

The require-checker that scans for types referenced but not required now also
reads *interface arguments*, not just raw allow/dontaudit lines: `staff_git_t`
was passed to `portage_read_ebuild()` and was invisible to the old check,
costing an extra build. Class perms do not need the same treatment - checkmodule
takes those from its own class table, and the apparent gaps are refpolicy's m4
perm macros (`manage_fifo_file_perms` and friends).

## Verification traps hit (so they are not hit again)

- The require-checker **must run as root**: without it the glob into the mode-700
  store expands to nothing, the declared-type set is empty, and every type looks
  like "not in policy". It now asserts it can see >500 types and fails loudly.
- CIL keeps `self`. Grep for `(allow staff_t self (...)` - searching for the
  expanded `staff_t staff_t` silently finds nothing and looks like a missing grant.
- A rule can be *documented* without being *written*: one batch replaced a comment
  with text claiming a grant and omitted the `allow` line, which the merge happily
  accepted. Verify in the loaded CIL, not in the source.

## Round log

- r3: found and removed the `neverallow` that made the home package unlinkable;
  granted `domain_read_all_domains_state(staff_t)` and the nvtop socket getattrs.
  Real denials 1,119 -> 858.
- r6-r8: re-scoped to enforcing-ready. Fixed the neverallow that made the home package uninstallable; granted htop/nvtop /proc and socket state, nginx->gate, psi, git+tmux portage traversal, dhcpcd, java's port bind, and io_uring `allowed`. **Fixed the setsebool relabelto block by satisfying the UBAC constraint** (~84 denials/capture -> 0). Real denials 1,119 -> ~40-56 per window.
- r5: ebuild/portage grants, psi, git+tmux traversal of the portage tree; and the finding that the setsebool relabelto denials are constraint-blocked, not allow-blocked (see the outstanding table).
- r4: batch of nine grants (nginx->gate, adb, fuse, the whole bwrap remount
  cluster, ptmx, setsched, ptrace, anon_inode widened). Real denials 748 -> 470
  by the 8-minute measure, and **zero in a 90-second window taken immediately
  after the merge**, with bwrap/nvtop/adb/nginx all running. Residual in later
  windows is the merge's own setsebool/semodule activity, which is why it is now
  an outstanding item rather than noise.

## Before enabling enforcement

1. Get the Outstanding table empty, or every row explicitly accepted as
   "this will fail and that is fine".
2. Re-capture over a quiet window and confirm the only AVCs left are the
   accepted ones.
3. Then, and only then, enforcement - as an announced, separate step.

## Round 15 - the coverage sweep, and the network half closed

### What "coverage" now means

Every running domain was enumerated from `/proc/<pid>/attr/current` and every
enabled service from `rc-status --all`, then each was audited. 36 domains are in
use. The ones with security weight:

| domain | who | state |
|---|---|---|
| `sysadm_t` | `sudo` work, and the whole Android emulator stack (`qemu-system-x86`, `adb`, `adbtrack`, `netsimd`, `bridge`) | **enforced** - was the last domain with a real backlog, see the network section |
| `staff_bubblewrap_t` | bwrap, `steamwebhelper`, the harness sandbox | enforced; 41 denials, both classes granted this round |
| `nginx_t` | the web UI | enforced; only the conntrack legacy below |
| `staff_t` | desktop session, the agent, node, llama-server | permissive by list; remaining classes settled |
| `mozilla_t`, `crow_t`, `pipewire_t`, `wireplumber_t`, `gpg_t`, `staff_gkeyringd_t`, `staff_dbusd_t`, `staff_sudo_t`, `staff_screen_t` | desktop | enforced, clean in the window |
| `sshd_t`, `xdm_t`, `xserver_t`, `getty_t`, `local_login_t`, `auditd_t`, `dhcpc_t`, `udev_t`, `systemd_logind_t`, `policykit_t`, `rtkit_daemon_t`, `devicekit_power_t`, `system_dbusd_t`, `init_t`, `kernel_t` | system | clean |

Audited and recorded rather than "fixed", because neither is normal and neither
has a policy-shaped answer:

- **`initrc_t` running `ckb-next-daemon`.** A long-running daemon sitting in
  OpenRC's init-script domain: `/usr/bin/ckb-next-daemon` is `bin_t`, so the
  init script's exec leaves it in `initrc_t` and it runs with that domain's broad
  access. refpolicy has no domain for it. Only a new domain fixes this properly;
  it is on no critical path, so it is an open item, not a grant.
- **`NetworkManager_t` running `iwd`.** That domain has no `dns_client` or
  `mdns` packet allow. Quiet today (no denials at all from it), but under
  enforcing iwd would be denied if it ever does mDNS or captive-portal DNS.
- Stopped services (`postgresql-17`, `lxc.artix`) get no triage: they are not
  running, so there is no evidence to work from. Their modules are loaded.

### The network half: every flow labelled, no blanket `unlabeled_t`

The ruleset was already deployed, and the deployed ruleset was verified
equivalent to `files/ruleset.nftables` (compared normalised live output against
the file; only nft's own rendering differs - `ipv6-icmp`, quoted `lo`). What was
missing was coverage of the flows the maps never named. Added:

| flow | label | why it is normal |
|---|---|---|
| DHCPv4 67/68, DHCPv6 546/547 | `dhcpc_client` -> `dhcpd_client_packet_t` | dhcpcd. refpolicy already allows the type; nothing had labelled the ports, which is why the blanket `unlabeled_t` grant in `desktop.system.base.te` existed |
| adb 5037, emulator 5554/5555 | `adb_server`/`adb_client` | the emulator console and the adb server; adb also connects *outward* to a device's :5555 for wireless debugging |
| mDNS 5353 for `sysadm_t` | `mdns` | 682 denials in 24h, all from `adbtrack`/`adb`/Chrome on `eno1` - it is adb's wireless-debugging discovery |
| loopback traffic no map classifies | `local_packet_t` (new) | the emulator's dynamic ports and the local services the desktop uses on loopback: the model router on :55555, the carrier on :8081, adb's sockets |

`local_packet_t` is deliberately **not** an `unlabeled_t` grant. It is applied by
`iif lo`/`oif lo` rules only, so it can never cover anything that leaves the
machine, and it is granted per domain (sysadm_t, staff_t, nginx_t) rather than to
everything. The alternative - leaving those flows unlabelled - means the local
model stack and the emulator are covered only by `staff_t`'s blanket
`unlabeled_t`, which is exactly the thing this round removes.

**The design depends on two measured facts.**

First, a map lookup with a missing key *leaves the value alone* rather than
clearing it: a mark set to 0xaa followed by a lookup in a map that did not
contain the port survived as `mark=170` in `/proc/net/nf_conntrack`. That is
what lets the loopback default stand where no port names the flow.

Second - and this cost a wrong first attempt - **a loopback packet passes both
chains**, so a loopback flow must be labelled by exactly one of them. The first
version set a loopback default and re-derived the label from the port map in
both chains. The two maps do not hold the same ports, so a browser connection to
`127.0.0.1:80` was `http_client` on the output side and `http_server` on the
input side, and the browser's next receive was denied against
`local_packet_t`/`http_server`. The rules now label loopback only in the output
chain, and the input chain's port-map lookups and conntrack repair are
`meta iifname != "lo"` / `meta oifname != "lo"`. Verified with a fixed source
port so the entry could not be confused with an older one:

    curl --local-port 45678 http://127.0.0.1:8080/  -> http_client_packet_t
    curl --local-port 45679 http://127.0.0.1:80/    -> http_client_packet_t

The fixed source port matters: reading "the first entry for dport=8080" showed
11 stale entries still carrying the old label and looked like the fix had not
worked.

### Conntrack entries older than the ruleset - the real pre-enforcement hazard

`nginx_t -> unlabeled_t:packet` on `:80` from `192.168.1.100` (65 times in 24h,
`netif=eno1`) looked like a labelling gap. It is not: the deployed ruleset maps
80, and new connections are labelled correctly. Those are **flows whose
conntrack entry predates the ruleset load**, so they carry no secmark and every
packet on them is unlabelled. Under enforcing they would be denied - including
the long-lived connection carrying this session.

Flushing conntrack would fix it and is forbidden. Instead the ruleset now
re-derives the label for established flows, but only for the direction that
*opened* the flow:

    ct state established,related ct direction original \
        meta secmark set tcp dport map @secmapping_in
    ct state established,related ct direction original ct secmark set meta secmark

so an inbound-original packet on :80 is re-labelled `http_server_packet_t` and
the repair is written back to the conntrack entry, while a reply packet is never
given the other side's label.

Verified live after the load, by reading the conntrack `secctx` of real flows:

| flow | secctx |
|---|---|
| `:55555` - unclassified loopback (the model router) | `local_packet_t` (was `unlabeled_t`) |
| `:8080` - classified loopback (the gate hop) | `http_client_packet_t` - the named label still wins over the loopback default |
| `:80` - the **legacy** entries from `branch` | `http_server_packet_t` - the repair worked on the pre-existing entries |

The ruleset carries 0 drop/reject rules, both chains are `policy accept`, loopback
ping and the `:8080` gate still answer (401 is the healthy response), and the
state was persisted with `rc-service nftables save`.

### The one category left unlabelled, and it is not a gap

Off-box traffic to *ephemeral ports on both ends* cannot be named by any port
map. A 24h scan leaves two clusters, and both are identified:

- `192.168.1.100` is **`branch`'s own SSH origin machine** (`last -x` shows
  `branch pts/2 192.168.1.100`). The flows are the operator's own remote
  sessions and their forwarded ports to `sysadm_t` processes; the `comm` field on
  a packet AVC is unreliable (it reports `swapper`, `htop`, even a JVM's
  `GC Thread#0` for the same flow).
- the emulator's own dynamic ports, which are loopback and therefore covered by
  `local_packet_t`.

An earlier claim that these were "concretely normal adb traffic" was not
supportable from the evidence, so it is recorded as **open, pending the
operator** rather than granted. Nothing on the critical path depends on it.

### The `unlabeled_t` grants that remain, and what they are for

Removing the blanket grants is the point of the round, but only where the traffic
can be named. What is left, with the reason:

| domain | verdict |
|---|---|
| `dhcpc_t` | **being removed** - DHCP is labelled now, and refpolicy already allows `dhcpd_client_packet_t`. Kept one capture longer only because leases are long and a renewal may not appear in the first window |
| `mozilla_t`, `gajim_t`, `shortwave_t`, `stremio_server_t` | kept for now - WebRTC, XMPP and BitTorrent choose remote ports dynamically, so no secmark can name them. These are the domains where "audit" ends in "the port is genuinely unknowable", and that is recorded rather than papered over |
| `ssh_t`, `staff_t` | kept for now; after this round their loopback and named-port traffic is all labelled, so the next clean capture decides whether anything is still using the blanket |

### Boot-time enforcement: the finding to act on

`/etc/selinux/config` says `SELINUX=enforcing` (unchanged since 2025-08-20), and
the running kernel is permissive. The boot log for this boot
(`/var/log/dmesg`, timestamped exactly at `uptime -s`) shows why this is not a
simple "it is permissive at boot":

    t=7.29s  audit: type=1404 ... enforcing=1 old_enforcing=0 ... res=1
    t=7.88s  SELinux: policy capability ...            (policy load)
    t=11.5s  audit: type=1400 ... mount_t ... locale-archive ... permissive=0

So **the box really does pass through enforcing early in every boot** - those AVCs
were enforced, not logged - and it then ends up permissive, with nothing on disk
explaining the flip: no `setenforce` anywhere in `/etc`, `/usr/local` or
`/lib/rc`, no `enforcing=0` on the cmdline, no `selinux` init script, no
`MAC_STATUS` record after boot. `/etc/local.d` is empty.

Two things follow, and the second is the important one:

1. Enforcement at boot is *survivable here*: the box ran enforcing through its
   early boot 30 days ago and came up cleanly. The only enforced denials in that
   log are the `mount_t` -> mislabelled `locale-archive` pair, and that
   mislabelling was fixed in an earlier round.
2. The mechanism is unexplained, which is its own risk: a boot that *starts*
   enforcing and is switched off by something I cannot identify is not a
   controllable safety boundary. This needs the operator's knowledge before any
   deliberate switch.

### Granted this round

| pattern | mechanism |
|---|---|
| `ssh_t -> ptmx_t:chr_file { read write }` (4) | `term_use_ptmx(ssh_t)` - ssh allocates a pty; sshd's side was already granted |
| `ssh_t -> user_tmpfs_t:dir { search }` (3) | raw allow; an ssh started from `~/tmp` inherits that cwd |
| `staff_sudo_t -> portage_ebuild_t:{dir search, file getattr}` (5) | `portage_read_ebuild(staff_sudo_t)` + a search allow. `sudo ./aud` and `sudo make -C <pkg> merge` become `staff_sudo_t`, so without this the policy cannot be triaged or maintained under enforcing |
| `staff_bubblewrap_t -> self:udp_socket { write }` (39) | raw allow; `steamwebhelper` writing to the UDP socket it created for mDNS multicast. Self access, so granted rather than dontaudited |
| `semanage_t -> self:process { getsched }` (2) | raw allow; during a merge |

Measured on the way: a two-hour capture filtered to the enforcing domains (the
seven permissive domains and my own census tooling excluded as self-inflicted)
contained **eight distinct patterns and nothing else**. Most of what looked like
new backlog was me: `iptables_t -> user_home_t` is `sudo nft list ruleset >
~/tmp/...`, and `sysadm_t -> staff_t:unix_stream_socket ioctl` is `ss`/`ls`
walking `/proc` under sudo.

### r15 round log

- Census over all 36 domains and all enabled services; every enforced domain's
  denials reduced to 8 distinct patterns.
- Network coverage closed: DHCP, adb, emulator, `sysadm_t` mDNS, and a scoped
  `local_packet_t` for loopback; conntrack repair for flows predating the
  ruleset, so enforcing cannot cut the session on a stale entry.
- Found the boot-time enforcement behaviour, which is a safety question rather
  than a triage one.
- Post-merge capture (`captures/2026-09-30-r15-post.audit`) is **3 denials, all
  `sysadm_t`**: the two deliberate unlabelled off-box packets, and one
  `sysadm_t -> staff_t:unix_stream_socket { ioctl }` from `sudo git` (admin
  tooling). `aud`'s draft module offers `corenet_sendrecv_unlabeled_packets(sysadm_t)`
  for the first pair - **not taken**: that is the blanket this round exists to
  avoid, and the traffic is unexplained rather than normal.
- Caught a clobber I introduced: the input chain was re-deriving loopback labels
  from the inbound map, which disagrees with the outbound one. Fixed by labelling
  loopback in the output chain only (`6471f52`); verified with fixed source ports;
  browser packet denials went to zero.
- Verified the network half live rather than in the source: `local_packet_t` on a
  fresh loopback flow, `http_client_packet_t` preserved on a classified one, and
  `http_server_packet_t` on the legacy `:80` entries that would otherwise have
  been denied under enforcing.

## Round 16 - the permissives dropped, and what that exposed

### The drop itself

All seven permissive flags were removed (`semanage permissive -d` for crow_t,
gajim_t, java_t, mplayer_t, staff_git_t, staff_t, stremio_server_t). They were
hand-made `(typepermissive X)` modules in the store with **no source anywhere in
the overlay** - so this also removes seven modules that the "no source" rule
forbade. The store went 107 -> 100 modules, and `semodule -l` now lists only
modules the overlay can rebuild.

**What it does not do: change anything yet.** Two things are worth being precise
about, because both are easy to get wrong:

- While the *global* mode is permissive (`/sys/fs/selinux/enforce` = 0), dropping
  a domain flag has no runtime effect at all: the denial is still logged, not
  enforced.
- The `permissive=` field in an AVC is **not** "is this domain permissive". Every
  AVC since the drop still reads `permissive=1`, because the field reports the
  *effective* mode for that denial - global mode is permissive, so every denial is
  unenforced. `permissive=0` appears only when enforcement is actually happening
  (at boot, before the box switches itself back). So the field cannot be used to
  find the gaps; the domain list and the policy are what answer that question.

### What the dropped domains actually need

Volume over the retained logs (~14 h), and only three of the seven appear at all:

| domain | denials | what it is |
|---|---|---|
| `java_t` | 7015 | **the Android build** - `gradlew`, `java`, `clang++`, `ndk-build`, `jspawnhelper` building the *tulkki* APK under `~/var/work` |
| `staff_git_t` | 370 | `git` (358) and `sh` (12) - the user's git wrapper |
| `staff_t` | 310 | the session, almost all of it `nnp_transition`/`nosuid_transition` when it launches those two |
| `crow_t`, `gajim_t`, `mplayer_t`, `stremio_server_t` | 0 | idle; nothing to fix, and no grants invented for them |

`java_t` is the "per-role application domains get no home access" class the ledger
already describes, at build-tool scale: home content write/setattr/unlink/create,
dir add_name/remove_name/setattr/watch, the `~/tmp` tmpfs as scratch, the JVM's
`execmem`, `/etc/env.d` (labelled `etc_runtime_t`) via `clang++` looking for the
toolchain, the cgroup reads, and `lib_t` execution for the NDK tools.

### The trap that cost two failed merges: `process2`

`nnp_transition` and `nosuid_transition` live in the **`process2`** class, not
`process` (refpolicy's `policy/flask/access_vectors`: `class process2 {
nnp_transition nosuid_transition }`). Writing them into `class process { ... }`
produces a *misleading* error from checkmodule:

    Class process would have too many permissions to fit in an access vector
    with permission nosuid_transition

which reads like a class-table/AV-slot defect (the same family as the
`io_uring:getattr` block) and sent me to the wrong fix - a hand-written CIL
statement, which then failed differently ("Failed to resolve permission
nnp_transition"). The cause of the misdiagnosis was my own AVC parser:
`tclass=([a-z_]+)` does not match `process2`, so the class name was silently
truncated to `process` in every listing this round. **Any tclass with a digit in
it was being mangled** - worth checking before trusting a pattern list.

Both grants now go in the .te, on the right class:

    class process2 { nnp_transition nosuid_transition };
    allow staff_t java_t:process2       { nnp_transition nosuid_transition };
    allow staff_t staff_git_t:process2  { nnp_transition nosuid_transition };
    allow staff_t ssh_t:process2        { nnp_transition nosuid_transition };

The session runs under `no_new_privs` (the harness sandbox), so without these a
build or the git wrapper cannot be launched *from the agent's session* at all -
the exec is refused. Launches from a normal terminal are unaffected.

### Granted this round

| pattern | mechanism |
|---|---|
| `java_t` -> user_home_t (file write/setattr/unlink/create, dir add_name/remove_name/setattr/watch) | `userdom_manage_user_home_content_files/_dirs(java_t)` + a watch allow |
| `java_t` -> user_tmpfs_t (dir and file) | `manage_dirs_pattern` / `manage_files_pattern` on the user tmpfs mount |
| `java_t` -> self:process execmem (99) | explicit allow, **scoped to java_t** rather than the global `allow_execmem` boolean - the JVM does not run without it, and this is the narrowest form |
| `java_t` -> etc_runtime_t (572) | `files_read_etc_runtime_files(java_t)` + dir search: `clang++` reading `/etc/env.d/gcc` to find a toolchain |
| `java_t` -> cgroup_t | `fs_read_cgroup_files(java_t)` + dir search |
| `java_t` -> lib_t:file execute_no_trans (97) | raw allow; the NDK executes toolchain binaries |
| `java_t` -> ptmx_t | `term_use_ptmx(java_t)` |
| `java_t` -> local_packet_t | Gradle daemon <-> workers over loopback |
| `staff_git_t` | user_tmpfs dir search, `staff_t:unix_stream_socket` rw/getattr/ioctl, `kernel_read_vm_overcommit_sysctl` (git's mmap heuristic), `shell_exec_t { map execute_no_trans }` (hooks/pagers) |
| `staff_t` -> devpts_t:chr_file | `script(1)` allocating a pty |
| `staff_t` -> proc_psi_t | `kernel_read_psi(staff_t)` |

### A readiness problem found in the merge itself

Every merge this round printed, after loading the modules successfully:

    Failed to calculate reverse dependencies for policy: qdepends returned 1.
    File ".../rlpkg", line 234, in relabel_packages
    AttributeError: 'str' object has no attribute 'unevaluated_atom'

The policy loads fine; what fails is the eclass' **automatic relabel step**
(`qdepends` cannot read the installed package set, and `rlpkg` then crashes on a
portage API change). Consequence: when the policy changes a file context, nothing
re-labels the filesystem - the module's `file_contexts` is updated in the store,
but the files keep their old labels until something runs `restorecon`/`rlpkg`
by hand. Nothing in this round depends on a file context change, so it has not
bitten yet, but it is exactly the kind of gap that shows up at enforcement time,
and it is the same toolchain breakage that already made `audit2allow` unusable.

### Deliberately not granted yet

- `java_t` -> `unlabeled_t:packet` (~95 each way): unclassifiable off-box remote
  ports during dependency resolution. The ruleset changed under this traffic today
  (loopback and the named ports are labelled now, so part of it is already gone),
  so a post-fix capture decides what is left. Not blanket-allowed meanwhile.
- `staff_bubblewrap_t` -> `fs_t:filesystem getattr` (17): Steam's statfs inside
  the sandbox. Cosmetic.
- `staff_t` -> `systemd_sessions_runtime_t:file { open read }`: `uptime` counting
  sessions from `/run/systemd/sessions/c4`. Cosmetic; grant if it matters.
- `sysadm_t` -> `staff_t:unix_stream_socket ioctl`: admin tooling only.
- `sysadm_t` -> self `execheap`: a CEF render thread; needs the `allow_execheap`
  boolean, i.e. a deliberate W^X relaxation.

## Round 17 - the boot question resolved, and the boot path cleared

### It is answered: a reboot brings the box up enforcing

The goal said the boot-time question had to be resolved before any switch. It is:

    $ objdump -T /sbin/init | grep selinux
      is_selinux_enabled
      selinux_init_load_policy

OpenRC's init imports `selinux_init_load_policy`, which is the libselinux entry
point that reads `/etc/selinux/config` and applies the mode. That is the
`enforcing=1 old_enforcing=0 res=1` record at t=7.3 s in the boot log, and the
AVCs at t=11.5 s carrying `permissive=0` prove the mode was still enforcing
*after* the policy load at t=7.9 s. The initramfs carries no policy (only
`lib64/libselinux.so.1`), so this is the mechanism.

**Consequence, and it is the important one: the running permissive state is a
leftover.** It cannot be the boot default - the config has said `enforcing` since
2025-08-20, nothing on the box calls `setenforce`, and OpenRC applies the config
at every boot. So an explicit `setenforce 0` was run after that boot 30 days ago
(the machine was rebooted three times that evening, 20:03/20:11/20:15), and
nothing has reset it since because the box has not rebooted.

So the "switch" is not a separate step waiting to be taken: **any reboot brings
the box up enforcing.** That is a materially different risk position from "we are
permissive and will decide later", and it is why this round went to the boot path
first.

### The boot path, cleared from the only hard evidence available

`/var/log/dmesg` is the boot log of the running kernel, and its AVCs carry
`permissive=0` - they were *enforced*, not merely logged. That makes it the only
direct evidence of what a real enforcing boot hits. Every pattern in it:

| enforced at boot | disposition |
|---|---|
| `mount_t` -> `portage_tmp_t:file {read}` x12, `dmesg_t` -> same x2 | **moot** - that was the mislabelled `/usr/lib/locale/locale-archive`, now correctly `locale_t` (the *user* component is still `staff_u`, which `restorecon` would fix) |
| `alsa_t` -> `device_t:chr_file {read}` x3 (`controlC1/C2`) | **stale** - every device under `/dev/snd` is `sound_device_t` now and `alsa_t` may read it, so nothing to do |
| `mount_t` -> `initrc_tmp_t:dir {mounton}` | already allowed |
| `kmod_t` -> `console_device_t:chr_file {read}` x4 | granted: `term_read_console(kmod_t)`, the interface `dmesg_t` already uses |
| `udev_t` -> `alsa_t:process {noatsecure rlimitinh siginh}` | `dontaudit` - inherited-fd bookkeeping, transition not blocked, nothing fails |
| `systemd_tmpfiles_t` -> `init_t:fd {use}` | `dontaudit` - inheriting the console fd from init; it only loses console printing |
| `udev_t` -> `unlabeled_t:lnk_file {read}` x1 (`name="run"`) | left; `/run` and `/var/run` are labelled `var_run_t` and matchpathcon agrees, so this is a stale link rather than a labelling gap |

### A real defect found outside the policy: the `/var/tmp` mount never happened

`/etc/fstab` line 36 asked for the portage build directory on a 32 GiB tmpfs:

    tmpfs-var-tmp /var/tmp tmpfs defaults,size=32768M,rootcontext=system_u:object_r:tmp_:s0

`tmp_:s0` is not a type - it is a typo for `tmp_t`. Tested both forms with a
scratch tmpfs mount (never touching /var/tmp):

    rootcontext=system_u:object_r:tmp_t:s0  -> mounts, label tmp_t
    rootcontext=system_u:object_r:tmp_:s0   -> "wrong fs type, bad option, bad superblock"

So that mount has failed on every boot and `/var/tmp` has been a plain directory
on the `/var` subvolume (84% full) instead of the intended tmpfs. Fixed, with a
dated backup at `/etc/fstab.20261001.bak`, `findmnt --verify` clean, and the
mount deliberately **not** performed by hand: it takes effect at the next boot,
where `/var/tmp` becomes RAM-backed and the current contents are hidden. Revert
by restoring the backup if a RAM-backed build directory is not wanted.

Note the adjacent, separate boot message - `SELinux: Context /run is not valid
(left unmapped)` - is **not** this bug and is harmless: `/run` is correctly
labelled `var_run_t`, so the mount is simply unmapped at the mount-option level
while the files still get their policy labels.

### The cushion is gone, so `staff_t` got the same audit

Dropping the flags removed the safety net that would have kept the session
permissive if the box rebooted: from now on a reboot enforces `staff_t` too, and
`staff_t` is both the user's session and this agent. So the same
denial-vs-policy check was run for it over the retained logs: 33 distinct
patterns, of which three were real gaps (everything else was already allowed,
including the `process2` transitions and the `devpts_t` grant from r16):

| pattern | disposition |
|---|---|
| `staff_t -> devpts_t:chr_file`, `-> staff_git_t/java_t:process2`, `-> proc_psi_t`, `-> systemd_sessions_runtime_t` | already allowed - verified with the full allow listing, not a `-p` filter (see the trap below) |
| `staff_t -> src_t:file { open read }` (30) | granted. `/usr/src` is `src_t`; refpolicy has `files_search_src()` for the directory but **no** interface for reading the files in it, so the read is a raw allow |
| `staff_t -> self:icmp_socket` + `-> icmp_packet_t:packet` | granted. The sandbox's `no_new_privs` means `ping` never transitions to `ping_t` and stays in `staff_t`; it then needs the raw ICMP socket and the packet label the ruleset puts on ICMP. refpolicy has no interface for either - `ping_t`'s own grants are raw allows too |
| `staff_t -> portage_db_t:file { open }` | granted (querying the installed-package database) |

**Trap worth keeping:** `sesearch -A -p read,write` (a comma list) reported
`devpts_t` and the `process2` transitions as denied when the loaded policy
contains them verbatim. Checking one permission at a time, or listing the allow
line without `-p`, gives the right answer. Two of this round's "gaps" were that
artefact and needed no change at all.

### dontaudit rules are written but globally stripped at load

Both of this round's `dontaudit` rules are in the store's module CIL -

    (dontaudit udev_t alsa_t (process (noatsecure siginh rlimitinh)))
    (dontaudit systemd_tmpfiles_t init_t (fd (use)))

- yet `sesearch -D` finds **no** dontaudit rule anywhere in the running policy,
for any domain. The store has dontaudits switched off (`semodule -DB`, which is
what one runs while debugging denials), and that strips them at link time.

What this does and does not mean:

- **It never changes an access decision.** dontaudit controls whether a denial is
  *logged*; the access is denied either way. So enforcement readiness is
  unaffected, and re-enabling them (`semodule -B`) would not grant anything.
- It does mean the entire "informational" class this ledger has been marking as
  `dontaudit` material - the 16 inherited-fd `noatsecure rlimitinh siginh`
  suppressions in this file among them - has been **logging all along**. That is
  worth knowing when a capture looks noisier than the policy suggests, and it is
  why counting AVCs overstates what would actually fail.
- Left as-is: switching a global store flag is the operator's call, not a side
  effect of writing a module, and nothing in the objective needs it.

### Post-merge triage

Strictly after the last r16 merge, the log holds **2 AVCs**, both the documented
`sysadm_t` -> `unlabeled_t:packet` off-box category (one from `libuv-worker`).
Nothing from the domains whose flags were dropped - though the desktop is idle,
so that is a weak signal for the app domains rather than a strong one.

### Round 17b - the source census, and the last unlabelled flows

**Every loaded module has a source, in both directions.** 100 modules loaded,
100 `.pp`/`.cil` in `/usr/share/selinux/mcs/`, from 50 installed `sec-policy/*`
packages: 13 from this overlay, 87 from the distro's packages. The overlay's
`refpolicy/` tree holds 82 of them; the other nine (`android`, `base`,
`bubblewrap`, `dracut`, `makewhatis`, `nginx`, `openrc`, `tmpfiles`, `wayland`)
come from distro packages and are not expected in the tree. Worth recording for a
different reason: the distro packages are refpolicy **20260616** while this
overlay pins **20250213**, so the box runs a mix - a future distro bump could
rename a type out from under the local modules, which is what the require blocks
are protecting against.

**Stremio's streaming server was the last reachable service riding a blanket.**
`server.js` binds `*:11471`, so a LAN player reaches it, and 11471 was not in any
map - `stremio_server_t`'s blanket `unlabeled_t` grant was the only thing covering
it. Now labelled `http_server` in `secmapping_in` with the specific allow.

**A new way to see the whole picture: read the secmarks out of conntrack.** Every
flow carries its secmark, so `grep secctx /proc/net/nf_conntrack` is a live census
of the labelling, no capture needed:

    56 unlabeled_t   48 http_client_packet_t   28 local_packet_t
     8 dns_client_packet_t   8 adb_client_packet_t   4 http_server_packet_t
     3 mdns_packet_t   1 adb_server_packet_t

The 56 unlabelled ones are two flows, both now identified:

- **Google FCM, TCP 5228**, and this is the attribution the earlier rounds could
  not make: `comm="slirp"`, `scontext=sysadm_t`, `daddr=173.194.221.188`. That is
  qemu's user-mode networking carrying the **Android emulator guest's** traffic to
  Google's push servers. Concretely normal for someone running an emulator, but the
  *remote* port is Google's choice, so no port map can name it. Options, both
  defensible and left to the operator: leave it denied (the emulator keeps working -
  80/443/53 are mapped - but push does not), or label unclassified *outbound*
  non-loopback flows with a new `dynamic_client_packet_t` and grant that to
  `sysadm_t` alone. The second is not an `unlabeled_t` grant and has a real
  security difference: it would apply only to locally-initiated flows, so an
  inbound connection to an unclassified local port would still be denied.
- **SSDP, UDP 1900** (inbound announcement from `239.255.255.250`, likely Stremio's
  or the browser's discovery). refpolicy already declares
  `ssdp_client_packet_t`/`ssdp_server_packet_t`, but **no domain holds them and
  there is no interface**. Deliberately **left unlabelled**: with no AVC and no live
  socket there is nothing to attribute the flow to, and labelling a flow whose
  domain has no allow *converts a blanket-covered flow into a denied one* - the
  mistake `local_packet_t` made with `mozilla_t` in r15. The fix is ready (label
  1900, grant the type to whoever a capture names) but it needs the attribution
  first.

**The enabled-but-stopped services have been examined as far as static evidence
goes.** `postgresql-17` and `lxc.artix` are both in the default runlevel and both
stopped, with **zero** AVCs in every retained log, so there is no behaviour to
triage. What can be checked is checked: PostgreSQL's paths are labelled exactly as
its module expects (`postgresql_db_t`, `postgresql_runtime_t`, `postgresql_etc_t`),
and LXC's match `matchpathcon` (`/var/lib/lxc` and `/var/lib/lxc/artix` are
`var_lib_t`, `/etc/lxc` is `etc_t`, `lxc-start` is `bin_t`) - this refpolicy simply
defines no container-specific types for that tree. So neither is a labelling gap;
the first *start* under enforcing would be the first real audit of them, and that
is recorded rather than guessed.

## Round 18 - the census tool fixed, DHCP retired, mail and XMPP labelled

### `ss` was the largest source of AVC noise on the box

A re-triage straight after the previous merge returned **8153 AVCs** - and every
one was mine: `ss_t -> <every other domain>:dir search`, from `ss -tulpnH`. That
is not a policy gap in the abstract; `ss -p` maps sockets back to processes by
walking `/proc/<pid>`, exactly what htop/nvtop needed, and 17k of those denials sit
in the retained logs. Two consequences, both worth fixing:

- under enforcing, `ss -p` would be **broken** - the socket-to-process mapping is
  the tool's whole point - and it is a normal admin tool, not an unusual one;
- every triage window I take is polluted by it, which is how a "8153-denial
  window" turns out to contain no real denials at all.

Treated exactly like `staff_t`: `domain_read_all_domains_state(ss_t)` for the
`/proc` walk, plus raw allows for the socket `getattr`s (`domain_getattr_all_domains`
covers only the process class). The verification is direct - run `ss -tulpnH`
again and count new denials; it should be zero.

### The `dhcpc_t` blanket is gone, on evidence

It was kept in r15 with the note "needs one capture to confirm". The evidence
arrived without a capture: the lease renewed at **08:16 on 1 Oct**, after the DHCP
labelling went in, and there are **zero** `dhcpc_t` packet denials since. Combined
with 67/68/546/547 being in the maps, the blanket was dead weight, so it is
removed.

### Mail and XMPP: normal flows that had no labels

Neither the mail ports nor the XMPP ports were mapped, so the mail plugin's IMAP
and the MTA's SMTP were covered only by `staff_t`'s blanket, and Gajim's XMPP by
`gajim_t`'s. Both are normal flows for this box, so they are labelled now:

    out: 25/465/587 -> smtp_client   110/995 -> pop_client
         143/993    -> mail_client   5222/5223 -> jabber_client

refpolicy already declares `smtp_client_packet_t`, `pop_client_packet_t`,
`mail_client_packet_t` and `jabber_client_client_packet_t`, so no new types.

**Two more unlabelled classes showed up in the post-merge census**, both left
alone on purpose and both worth naming so the next round does not re-derive them:

- **`192.168.1.104:8008`** - a peer that has not appeared before, on the port
  Chromecast-style devices use. There is no packet type for it and nothing
  attributes the flow to a domain, so labelling it would be the SSDP mistake
  (converting a blanket-covered flow into a denied one). Recorded, not labelled.
- **Legacy loopback flows** (`127.0.0.1 <-> 127.0.0.1`, 10 entries): these predate
  the loopback labelling, and the r15 repair was deliberately restricted to
  non-loopback (`meta iifname != "lo"`) so the two chains can never disagree about
  a loopback flow. They clear as the connections recycle; new loopback flows are
  labelled. Nothing to do.

**The check that makes this safe is worth naming**: before labelling a port, ask
whether the domain that uses it already holds the type. `staff_t` does - it has
`client_packet_type`, which is why the mail plugin and `system_mail_t` (the MTA
domain here; `mta_t` does not exist in this policy) need no change. `gajim_t`
does **not**, so labelling 5222 without granting the type would have converted a
blanket-covered flow into a denied one - the `mozilla_t`/`local_packet_t` mistake
from r15. The grant and the label therefore land in the same change.

## Round 19 - the census tools finished, and 5228 attributed

### `ss` needed two interfaces, not one

`domain_read_all_domains_state` is **dir-only** (`kernel_search_proc` plus
`domain:dir list_dir_perms`), so granting it removed the 17k directory denials but
left 113 `process getattr` ones in the very next window. The companion interface
`domain_getattr_all_domains` is literally `allow $1 domain:process getattr`, and
that is what completes the `/proc` walk. The rest of what a root-run census needs:
`CAP_SYS_PTRACE` and `dac_read_search` (reading other processes' `/proc`), the
`cap_userns` form of `sys_ptrace`, and the last socket classes
(`rawip_socket`, `packet_socket`, `netlink_audit_socket`).

Verified the way that matters: run `ss -tulpnH` and `ss -tanpH` and count - **zero**
denials, where the same two runs produced ~8153 before r18.

### `sudo nft -f <file in the overlay>`

The netfilter tools run as `iptables_t`, so loading a ruleset straight from the
repo tripped `iptables_t -> portage_ebuild_t:dir search`. Granted the same repo
access `staff_sudo_t` has, and proved it: `nft -c -f` on the repo file now
produces no denials.

### `:5228` is now attributed to sockets, not just a `comm`

With `ss -p` working again, the socket owners can be read directly:

    qemu-system-x86  (sysadm_t)  -> 142.251.1.188:5228
    netsimd          (sysadm_t)  -> 209.85.233.188:5228, 173.194.220.188:5228

`netsimd` is the Android emulator's network simulator: it holds the guest's FCM
connection. That is the Android emulator doing what an emulator does, and the
remote port is Google's choice, so no port map can name it - the same conclusion
as r17b, now with the sockets rather than a softirq `comm` behind it.

The other two unattributed flows are now closed as far as they can be:

- `192.168.1.104:8008` - every entry is **TIME-WAIT** with no owning process left,
  so the flow is already gone; it ages out of conntrack.
- SSDP `:1900` - no socket holds 1900, so the flow was inbound multicast to a
  port nothing was listening on.

Both stay unlabelled on purpose: there is nothing to attribute, and labelling a
flow whose domain has no allow is a regression, not coverage.

### `wip/README.md` rewritten

It still described the local gate hop as a "known residual ... continues at a low
rate" (fixed in r15) and predated the boot finding, so it now says what is
actually true, keeps the deploy order, and points at this ledger for the live
state. The old `network-draft.te` is kept for the reasoning it records.

## Round 19b - the blankets are gone, replaced by a named type

### `dynamic_packet_t` replaces six `corenet_sendrecv_unlabeled_packets()` grants

The objective says no wholesale `unlabeled_t` grants, and six per-domain blankets
survived from before the labelling existed. They are gone now, replaced by a type
of our own:

    type dynamic_packet_t;
    typeattribute dynamic_packet_t packet_type;

applied by fallbacks in **both** chains - `ct state new`, non-loopback, placed
*before* the port maps so a named label always wins:

    ct state new meta iifname != "lo" meta secmark set "unclassified"
    ct state new meta secmark set tcp dport map @secmapping_in     # and it wins

Granted to the domains that genuinely use unnameable ports: `mozilla_t` (WebRTC
picks UDP ports per call), `gajim_t`, `shortwave_t` (station ports), 
`stremio_server_t` (BitTorrent picks its listen port at runtime and receives
inbound peers on it), `ssh_t` (any port), `staff_t`.

**Honesty about what this changes.** For those seven domains it is
coverage-equivalent to the blankets they replace - saying otherwise would be
marketing. What it does change: the traffic is now *labelled* with a type we
control and granted per domain, and `unlabeled_t` packets should no longer occur
at all, so any future one is a signal that labelling broke rather than a fact of
life. The genuine tightening is for flows *no* domain is granted: an inbound
connection to an unclassified local port is still denied for everyone else.

Verified in the loaded policy and in conntrack, not in the source:

| check | result |
|---|---|
| a new unclassified off-box flow | `secctx=dynamic_packet_t` |
| named labels still win (`:443`, `:8080`, `:55555`) | `http_client`, `http_client`, `local` |
| domains holding `dynamic_packet_t` | all seven |
| **domains still holding `unlabeled_t`** | **none** |

One nftables detail: `dynamic` is a **reserved word**, so the secmark object is
named `unclassified` while the policy type stays `dynamic_packet_t`.

### A correction I owe the ledger: the DHCP "proof" was not one

r18 recorded the `dhcpc_t` blanket as "removed on evidence" - the lease renewed at
08:16 and there were zero `dhcpc_t` packet denials. That was wrong, and in a way
worth writing down: the hand-written **`desktop.system.cil`** carried its own
`(allow dhcpc_t unlabeled_t (packet (send recv)))`, independent of the `.te` line
that was deleted. The blanket was still in force, so the zero-denial observation
was equally consistent with the blanket covering an unlabelled path. It proved
nothing.

Both sources are removed now. `dhcpc_t` holds `dynamic_packet_t` as an explicit
safety net instead - it is the one flow whose failure would cut this box off the
network - and it can be dropped once a renewal shows `dhcpd_client_packet_t` in
conntrack. The ports are mapped in both directions (67/68 and 546/547), so it
should never be used.

### The one transient this creates, and why it self-heals

The migration removes the blankets while flows that were labelled *before* the
fallback existed are still alive. A conntrack entry keeps the label it was given,
so those packets stay `unlabeled_t` and - with the blanket gone - are now denied
until the connection recycles. It shows up immediately: `stremio_server_t ->
unlabeled_t:packet` on its long-lived tracker/CDN connections, and 48 unlabelled
entries still in conntrack (5228, 8008, 8081, a couple of ephemeral ones).

That is the same shape as the r15 gate-hop residual, it clears as connections
recycle, and forcing it would mean a conntrack flush, which is never done here.
Worth knowing before the switch: a flow that predates the *ruleset*, not just this
change, is the thing that can be denied on the first packet after enforcement is
turned on. New flows are labelled correctly - verified with a fresh unclassified
connection, which came out `dynamic_packet_t`.

**Trap for the list: the same grant can exist in two places.** `desktop.system.cil`
is a hand-written module alongside the `.te` files, and `grep`ing the source tree
for a blanket finds only one of them. Grep the **store** (`/var/lib/selinux/...`)
when retiring a grant - that is what the policy actually carries.

## Round 20 - the full-log sweep, java_t, nuvio and the browser

### A whole-log sweep, and a warning about the tool that does it

Every distinct denial in **all** retained logs - 515 patterns - was checked
against the loaded policy, one permission at a time. The screen flagged ten
patterns as still-denied; three were real, and the rest were already documented
(sysadm_t's emulator traffic, stremio's pre-fallback flows).

**The warning matters more than the result**: the sweep reported
`staff_t -> staff_git_t:process2 { nnp_transition nosuid_transition }` as denied
when the loaded policy contains that allow verbatim, and did the same for java_t's
tmpfs permissions. Its per-pattern verdicts are therefore a *screen*, not a
finding - each one needs `sesearch` run directly on it before it is believed. The
same lesson has now bitten this ledger three times (the `-p` comma list, `-t self`,
and this), so it is recorded as a standing rule rather than an incident.

### java_t could not listen

The screen's real hits were all java_t, and r16 had granted `bind` on unreserved
ports but **not `listen`/`accept` themselves**:

| what was missing | why it matters |
|---|---|
| `java_t self:tcp_socket { listen accept }` | the Gradle daemon binds a localhost port for its workers and listens on it - without this a build fails the moment enforcement is on |
| `corenet_tcp_bind_generic_node`, `corenet_udp_bind_generic_node` | the `node_bind` denials (242 of them) |
| `java_t user_tmpfs_t:file map` | `manage_files_pattern` covers read/write but **not** mmap, and the build mmaps its scratch files |

Granted and verified; the Android build's toolchain path is now complete.

### nuvio - user request

`~/bin/nuvio` is a wrapper that runs the newest `*.AppImage` from
`~/bin/appimages` with `APPIMAGE_EXTRACT_AND_RUN=1`, **because this host has no
`/dev/fuse`** - so the payload unpacks into `$TMPDIR` and executes from there.
Two real blockers, both found by checking the labels rather than the app:

1. **The AppImage was labelled `xdg_downloads_t`** - a Downloads label on a file
   sitting in `~/bin/appimages` - and `staff_t -> xdg_downloads_t:file execute` is
   **0**. Under enforcing nuvio could not have started at all. Relabelled with
   `restorecon` to `user_bin_t`, which its path implies and which `staff_t` may
   execute.
2. **`TMPDIR` is unset, so extraction landed in `/tmp`** (`tmp_t`) - and
   `staff_t -> tmp_t:file execute` is **0**, so the extracted payload could not
   run even after (1). The wrapper now sets `TMPDIR="$dir/.run"`; that directory
   is `user_bin_t` and new files created in it inherit that, which was probed
   rather than assumed.

Verified: running the AppImage runtime produced **zero** AVCs. Everything else
nuvio needs was already in place, because it runs in `staff_t`:
`sound_device_t` with `{ append getattr ioctl lock map open read write }`,
`pipewire_t`/`pulseaudio_t` unix sockets, `dri_device_t` with the same full set
plus `map`, `http_client`/`dns_client` through `client_packet_type`, and
`dynamic_packet_t` for stream ports no map names.

A scan of `~/bin` for the same class of problem found nuvio was the only
exec-hostile case: `~/bin/stremio-server` is deliberately `stremio_server_exec_t`
(that label *is* the domain transition), and `~/bin/ds-usage` is `user_home_t` -
executable by `staff_t`, just untidy.

### Firefox video and sound - user request, verified rather than changed

`mozilla_t` already holds everything media needs, and there are **zero** denials
in those classes:

| access | held |
|---|---|
| `sound_device_t:chr_file` | `{ append getattr ioctl lock map open read write }` |
| `dri_device_t:chr_file` (VA-API/rendering) | the same full set |
| `v4l_device_t:chr_file` (camera) | `{ getattr ioctl lock open read }` |
| `pipewire_t:unix_stream_socket` | `connectto` |
| `pulseaudio_t:unix_stream_socket` | present (`mozilla_t` is a `pulseaudio_client`) |

So no change was needed: the browser's audio and accelerated video are already
permitted, with the actual devices (`/dev/dri/renderD128`, `/dev/snd/controlC0`)
labelled `dri_device_t` and `sound_device_t` as the policy expects.

## Round 22 - the shared /home/user, and what the blanket relabel did

### The design, now recorded

`branch`, `stem` and `leaf` are three identities sharing one `/home/user`, each
with its own SELinux role/user. That makes the *user component* of those files a
design decision, not housekeeping - and a relabel that forces one identity across
the tree is a change that should not happen.

### What the broad relabel did, and the correction

r21's `restorecon -RF /` applied the policy's **defaults**: it flattened the whole
home into `user_home_t` (375,425 changes), sweeping up every type-specific path -
`~/.cache` lost `xdg_cache_t`, `~/.local/bin` lost `user_bin_t`. I mis-described
that earlier as "user-component fixes"; the dominant effect was the *types*.

The corrected rules, now in the local db and recorded in `fcontexts.local`:

    /home/user                                  sysadm_u:user_home_dir_t
    /home/user/\.local/src(/.*)?                 staff_u:user_home_t
    /home/user/\.local/src(/.*)?/\.git(/.*)?      staff_u:git_home_t
    /home/user/\.local/share/pnpm(/.*)?          staff_u:user_bin_t

Note what is **not** there: a broad `/home/user(/.*)?`. My first version had one,
and it flattened the type-specific paths - the local db is consulted *first*, so
its rules beat both the homedir template and the xdg/mozilla modules. The home
*directory* is `sysadm_u`; the tree keeps the types it should have. The corrected
pass (692,902 changes) restored `mozilla_xdg_cache_t` (18,067), `xdg_config_t` and
`mozilla_home_t` (4,443/2,325), `xdg_cache_t` and `android_home_t`, while keeping
`src` on the home_t's and pnpm executable.

**Why the local db and not a module `.fc`**: libselinux consults
`file_contexts.homedirs` *before* `file_contexts` for paths under a home, so a
module-level rule for `/home/user` would be shadowed by the generated template.
The local db is checked first and is the only layer that can override it. It is
not part of the module store, which is why the rules are recorded in the repo with
their `semanage` commands.

### Two things checked rather than assumed

- **`setfiles_t` already holds `can_change_object_identity`.** The relabel runs as
  `staff_u:sysadm_r:setfiles_t` (the exec transition, even through sudo), and the
  UBAC constraint therefore passes for cross-user relabels. No grant was needed,
  and my earlier worry that "every relabel would be denied under enforcing" was
  wrong.
- **htop is not being blocked.** Reading `/proc/<pid>/attr/current` - the call
  `getpidcon()` makes - succeeds both unprivileged and as root, the file is mode
  666, and **zero** AVCs are produced. `staff_t` already holds
  `domain_read_all_domains_state`. Whatever was missing in htop's security column,
  it was not SELinux, and nothing needs granting. (If htop is run inside a
  sandbox - flatpak/bwrap - then the sandbox's own domain is the one that would
  need it.)

### The detached processes

Background `sudo` commands outlive the shell that started them: when a tool call
ends or times out, the root child is reparented to init and no longer appears in
DSH's job tracking. That is the harness's process model, not a DSH bug - but it is
my mess to avoid, because it is how several restorecons ended up running
concurrently over the same trees. The UI's job list being empty is a *separate*
problem: the `workspace`/`session-controller` services are still `pending` from
the startup `scandir` failure, which a `dsh restart` clears.

## r23 - the last blockers before the reboot (2026-10-03)

Re-tested every **enforced** denial from the 12:19:35-12:32:40 enforcing window
(39 distinct source/target/class tuples) against the policy loaded after the r21b
merge. **34 were already allowed** - nginx's cache, the greetd session
entrypoint, `initrc_state_t`, rtkit's realtime scheduling, crow, mozilla,
pipewire. Five were not:

- **`nginx_t -> http_port_t:tcp_socket name_bind`** - not a module gap but a
  boolean. `nginx_enable_http_server` ships **off**, so the nginx module's bind
  rule is inactive and the master dies with `bind() to 0.0.0.0:80 failed (13:
  Permission denied)`. This, not the cache getattr, is what actually kept nginx
  down on the enforcing boot, and it survives every policy rebuild because it is
  a store setting rather than a rule - hence the new `booleans.local`.
  `nginx_can_network_connect` stays off deliberately: the proxy target :8080 is
  `http_cache_port_t`, allowed unconditionally.
- **`staff_t -> user_runtime_t:dir watch`** - GLib file monitors watching
  `/run/user/1000`. refpolicy has no watch interface for that type and `watch`
  is not under the UBAC constraint, so r23 adds the raw allow next to the
  `var_lib_t` one it mirrors.
- **four `dhcpc_t -> *:packet` denials**: `http_client_packet_t` (3075),
  `dns_client_packet_t` (425), `mdns_packet_t` (41), `unlabeled_t` (30 recv +
  8 send). The first three are dhcpcd holding an `AF_PACKET` socket: it is
  handed every flow's packets and each is checked against its secmark. DHCP's
  own packets are marked `dhcp_client`; these are other flows' traffic dhcpcd
  has no use for, so they stay **denied** - nothing fails - and they are the
  reason a boot carries ~3.5k AVCs. They cannot be silenced with `dontaudit`
  while the store is built with dontaudits disabled (`sesearch -D` returns 0
  rules), which is the open decision recorded elsewhere.

### The `unlabeled_t` half is not noise - it was IPv6

`accept_ra=0` on both interfaces, so the kernel is not doing SLAAC: **dhcpcd** is
what keeps `2001:14bb:ac:9012::/64` and the default route alive, and it does that
through a raw socket reading router advertisements. Those are multicast ICMPv6,
which never enters conntrack, so every `ct state new` / `established,related`
guard in `ruleset.nftables` misses them and they arrive with **no secmark at
all**. Under enforcing the receive is denied, the lease lifetimes run out, and
IPv6 dies about half an hour after boot - while IPv4 keeps working, so it would
have looked like an unrelated mystery.

Fixed in the ruleset, not by granting `unlabeled_t`: **ICMP and ICMPv6 are now
labelled from the protocol alone, in every conntrack state**, with a
`ct state untracked` fallback for anything else off the loopback. `ct state new`
was never the right guard - a packet on a flow whose conntrack entry carries no
secmark is labelled *empty* by the `established,related -> ct secmark` line, and
multicast ICMPv6 is frequently untracked outright, so no state guard reaches it.

Verified under enforcing: `ping6 ff02::1%eno1` went from `0 received` with five
`permissive=0` denials to `2 received, 0% loss` with **zero** AVCs. The router
advertisements dhcpcd needs are the same protocol and the same fix, and
`dhcpc_t` already holds `icmp_packet_t` - no new allow was needed, the packets
were simply never classified. The three `dhcpc_t` packet types above stay denied.

### Two things checked rather than assumed

- **The LAN ingress path is already clean.** nginx packet denials for the
  browser (192.168.1.106 -> :80) stop at the previous boot; the current ruleset
  marks them, and the live established connection produces no `packet` denial.
- **dontaudits really are absent**: `sesearch -D` returns **0** rules, so a
  `dontaudit` is not available as a silencing tool on this store.

## r23c - the htop domain (started, not finished)

Asking for htop's SECURITY column to work and **only** htop's means a domain of
its own, because SELinux cannot key a rule on a binary: once `staff_t` holds a
permission, `ps`, `top` and `pgrep` hold it too. So `desktop.home.htop` gives
`/usr/bin/htop` its own `htop_exec_t` / `htop_t` with `domain_getattr_all_domains`,
and nothing else changes domain.

The mechanism is worth recording because it is invisible in the audit log.
Reading `/proc/<pid>/attr/current` goes through `selinux_getprocattr()`, which
checks `process getattr` against the **target** domain and passes **no audit
data**. So the denial never reaches `ausearch` - htop printed `n/a` and the log
was empty, which is why the earlier "0 AVCs, so not SELinux" conclusion was
wrong. `ps` cannot do it today either; it shows `-` for exactly the same reason.

**State: not finished.** The domain compiles, `/usr/bin/htop` is relabelled
`htop_exec_t`, and a permissive run of the new domain produced ten denial groups
that are now all closed - `getcap` on every domain, `/proc/sys/kernel`,
`nsfs`, nscd, `/dev/tty`, htoprc write, `setcap`, `cap_userns sys_ptrace`, and
the shell's signal/sigkill - with **zero** AVCs on two further runs, one of them
under enforcing. But the column still shows `n/a` under enforcing, so at least
one permission is still missing and it will not show up in the audit log either.
Deferred to after the enforcing reboot; the next step is to find it from the
htop side (its own `getpidcon()` path and which field id the config actually
enables) rather than from the log.

## r24 - the 2026-10-03 enforcing boot

The box came up enforcing for real. Three things were broken, and only one of
them was the policy gap I expected.

### The user session: `checkpath` was mislabelled

`/usr/libexec/rc/bin/checkpath` was `tmpfiles_exec_t` while all 45 other helpers
in that directory are `bin_t`. The refpolicy tmpfiles module labels that path, so
**every** `checkpath` call by **any** init script silently transitions into the
system tmpfiles domain - and under enforcing `staff_t` cannot even `lstat` it.
The denial produces no AVC, so it is invisible to `ausearch`.

`/etc/init.d/user`'s `start_pre` calls `checkpath` for `/run/openrc/user/$user`,
so the session's state directory was never created, `rc-environ` had nowhere to
write its environment, and the session's services did not come up - which is why
dsh had to be started by hand. Fixed in the local db (`fcontexts.local`), and
verified directly: running `checkpath` now creates `/run/openrc/user/branch`,
which had never existed.

### nginx: not SELinux this time

`[emerg] bind() to 192.168.1.110:80 failed (99: Cannot assign requested
address)`. dhcpcd started at 14:06:08 and nginx tried ten seconds later; dhcpcd's
init script runs `-q` and forks before the lease arrives, and its `provide net`
lives in the `nonetwork` runlevel, so nginx's weak `use net` orders it after
dhcpcd *starting* rather than after the address existing. Fixed with
`command_args="-q -w"` in `/etc/conf.d/dhcpcd` and a hard `rc_need="dhcpcd"` for
nginx. Not a policy item.

### The rest of the boot's denials

Ten more, all now granted: supervise-daemon writing the session's state straight
into /run, udev reading the seat file, xauth's own dgram socket, the DSH sandbox
reading a symlink out of ~/bin (that is how it execs a shell inside the sandbox),
mozilla's psi memory file (r21b had only its directory), gtk's config dir, the
font-cache symlink and the compositor tmpfs map, crow opening its own config,
and pipewire reading the pulse pid file.

### htop: waived

The `htop_t` domain is removed - module unloaded, binary back to `bin_t`. It
could not have worked: htop runs inside `screen` and inherits `staff_screen_t`'s
terminal fd, so the domain change broke `fd use` before any question about
reading labels arose. The user will run htop as root instead, and the
`sysadm_t domain:process getcap` grant that already exists for that is the
sanctioned route.

## r25 - the 2026-10-03 enforcing boot, third pass (the 14:31 boot)

The session came up by hand again, and this time the log said why in volume:
**844 denials** of

    staff_t -> initrc_state_t:fifo_file read   name="supervise-user.branch.ctl"

r21 had granted the initrc_state_t *directory* and *file* permissions but never
the **fifo** the user session actually talks through, nor the `unlink` that
retires it, nor the `rmdir`/`relabelfrom`/`setattr` on the tree above it, nor
`setgid` for the session init dropping to the user. All of that is here now.

The `checkpath` relabel from r24 did work - this boot got past it and stopped
one layer further in, which is the only reason the fifo denial is visible at all.

nginx got past the address too: the wildcard listen removed the error-99 class
entirely, and it then died on

    open() "/run/nginx/nginx.pid" failed (13: Permission denied)

because checkpath creates `/run/nginx` as `initrc_runtime_t`, for which
refpolicy has no fcontext and `nginx_t` had no permission at all - not even
`search`.

Also granted: crow reading its own config's attributes, and mozilla's temp-file
execution, nvidia shader cache, gtk config read and psi open.

### Firefox is not an SELinux problem (recorded so it is not re-investigated)

A theme install fails with "Couldn't update your theme. Check your connection
and try again." Making `mozilla_t` a **permissive type** - which allows every
check and still logs the denial - produced **zero** AVCs, and the install still
failed. So there is no denial for that operation, audited or not. The scope was
deliberately widened rather than narrowed for that test: a permissive type is
the strongest available instrument, and it came back negative. Nothing in the
policy is responsible, and the permissive entry was removed again.
