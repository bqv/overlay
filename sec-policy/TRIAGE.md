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
