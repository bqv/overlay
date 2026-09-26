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
| network: mosh 60001/2, nginx :80, the local :8080 gate hop, mDNS 5353, ssh/http/dns/icmp | granted | secmark labelling + packet-type allows; see `wip/README.md` |

## Outstanding

| pattern | what breaks under enforcing | plan |
|---|---|---|
| `staff_t -> self:io_uring { getattr }` (nvtop) | nvtop cannot stat io_uring fds | **blocked**: checkmodule's class table has `io_uring:getattr` but the policy's does not, so declaring and allowing it makes semodule fail with `Failed to resolve permission getattr`. Kernel-vs-policy class-table mismatch, not a policy bug - revisit after a libsepol/base-policy rebuild |
| `mozilla_t -> cgroup_t:file { getattr }` (WebContent reading `/sys/fs/cgroup/*/cpu.max`) | the browser cannot read its cgroup | grant via the cgroup-getattr interface |
| `staff_t -> policy_config_t:dir { getattr }` on `/etc/selinux/mcs/policy` (from bash) | a shell cannot stat the policy directory | identify the caller, then grant |
| `staff_t -> staff_t:process { ptrace }` (`node-MainThread`, 21/capture) | the harness could not ptrace | find what asks for it |
| `staff_t -> node_t:tcp_socket { node_bind }` (`adb`, 19/capture) | adb cannot bind its node port | legitimate for adb -> grant |
| `staff_bubblewrap_t -> {proc,debugfs,configfs,pstore}_t:filesystem { getattr }` | statfs on those pseudo-filesystems fails | `kernel_getattr_*` interfaces |
| `semanage_t -> semanage_store_t:{file,dir}`, `policy_config_t:file`, `file_context_t:file` | `semanage` cannot write the policy store | legitimate for the admin tool -> grant |
| `nginx_t -> unlabeled_t:packet { send recv }` on 127.0.0.1:33278 <-> :8080 | nginx cannot talk to the gate | the legacy conntrack entry that predates the 8080 mapping. Clearing it needs a conntrack flush, which is **not** done - it would reset the session. Self-heals when the connection recycles |

## Before enabling enforcement

1. Get the Outstanding table empty, or every row explicitly accepted as
   "this will fail and that is fine".
2. Re-capture over a quiet window and confirm the only AVCs left are the
   accepted ones.
3. Then, and only then, enforcement - as an announced, separate step.
