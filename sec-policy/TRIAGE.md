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
| network: mosh 60001/2, nginx :80, the local :8080 gate hop, mDNS 5353, ssh/http/dns/icmp | granted | secmark labelling + packet-type allows; see `wip/README.md` |

## Outstanding

| pattern | what breaks under enforcing | plan |
|---|---|---|
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

## Round log

- r3: found and removed the `neverallow` that made the home package unlinkable;
  granted `domain_read_all_domains_state(staff_t)` and the nvtop socket getattrs.
  Real denials 1,119 -> 858.
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
