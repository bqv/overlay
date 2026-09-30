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
