# sec-policy

Hand-written, application-scoped MCS policy for a `staff_u` desktop, layered on
refpolicy 2.20250213 through the `selinux-policy-2` eclass. Built as real
packages in the `local` overlay, not as hand-installed `.pp` files.

## Target: enforcing

The end state of this policy is SELinux in **enforcing** mode on this box, so
every AVC is a work item rather than noise. The rules used to triage one:

- **legitimate access** -> grant it, using the refpolicy interface if one exists
  (`domain_read_all_domains_state`, `kernel_getattr_proc`, ...) and a raw allow
  otherwise;
- **genuinely unwanted** -> leave it denied, and write down what will then fail;
- **dontaudit** only where the denial causes no functional failure - it hides a
  problem rather than fixing it, so it is never used to make a real failure
  quiet.

Enforcement is not switched on until no unhandled denial remains. It is the one
change that can lock the operator out, so it is an explicit, separate step.

Captures go stale the moment a module is merged: always re-capture and re-triage
after a reload, with `sudo ./aud "10 minutes ago" <name>`.

A denial inventory is worth little until self-inflicted noise is removed from
it - commands like `grep`/`python3` walking `/var/db/pkg` produced 61% of the
AVCs in one capture, and attributing by `comm=` is what makes the rest visible.

## Packages

| package | modules |
|---|---|
| `selinux-desktop-system` | `desktop.system.base`, `desktop.system.mosh`, `desktop.system`*, `desktop.system.users`* |
| `selinux-desktop-home` | `desktop.home`, `.pipewire`, `.shortwave`, `.firefox`, `.stremio`, `.gajim`, `.crow`, `.openrc` |

`POLICY_TYPES="mcs"`; `selinux-desktop-home` depends on `selinux-desktop-system`.

Each app module is a `<name>.fc` / `<name>.if` / `<name>.te` trio under
`<package>/files/`, listed in `MODS` (bare names) and `POLICY_FILES` (with
extensions) in the ebuild. \* = recovered, see below.

## Recovered modules

`desktop.system` and `desktop.system.users` existed in the running module store
but had no source in this overlay, so the overlay could not rebuild the box.
Both are now `.cil` files in `selinux-desktop-system/files/`, listed in
`MODS`/`POLICY_FILES`.

They were recovered from `/var/lib/selinux/mcs/active/modules/400/<name>/cil` -
the CIL that libsemanage compiles the policy from. This is a **lossy**
recovery: that `cil` is the expanded form (macros expanded, comments gone,
`require` rewritten as `cil_gen_require`), and the `hll` beside it is the
original binary `.pp`. The hand-written `.te` is gone for good.

The eclass does not *compile* `.cil` (the refpolicy build Makefile only globs
`*.te`), but it does copy and install `.cil`, and `semodule` accepts CIL
directly - so shipping `.cil` works. Mind the mode: portage's `userpriv` phase
cannot read a `0600` file, so these are `0644`.

`desktop.system.users` is the three-tier user model: Linux accounts
`stem`/`branch`/`leaf` with roles `stem_r`/`branch_r`/`leaf_r`, domains
`stem_t`/`branch_t`/`leaf_t`, and per-tier dbus/systemd/WM domains. It is
currently **inert** - see Known issues.

## Method: denials drive the policy

    sudo ./aud "2 hours ago" my-capture
    sudo ./aud "14:20" my-capture

`aud` runs `ausearch | tee captures/<date>-<name>.audit | audit2allow -Revl |
tee captures/<date>-<name>.te | less +F`. It must run as root. The `.audit` is
raw evidence; the `.te` is an audit2allow draft. Neither is build input - a rule
is triaged out of the draft into a module by hand.

Triage conventions, as practised in the existing modules:

- every `allow` is annotated with the app that caused it (`# ckb-next`, `# rofi`)
- rules considered and rejected stay commented, with the reason (`# openrc-user`, `# pgrep?`)
- inherited-fd noise (`noatsecure rlimitinh siginh`) becomes `dontaudit`, not `allow`
- audit2allow's boolean hints (`##!!!! This avc can be allowed using...`) are
  recorded but overridden deliberately

## Building

    sudo make -C selinux-desktop-system compile   # manifest + clean compile
    sudo make -C selinux-desktop-system merge     # install + load
    sudo make -C selinux-desktop-home   compile

`desktop.home.pipewire.if` must not redefine `pipewire_domtrans`: the base
policy's `apps/pipewire.if` provides it, and m4 fails the home build with
"duplicate definition".

## refpolicy

`refpolicy/` is a pristine upstream tree, 2.20250213, kept **for reference
only** - the ebuilds do not read it; `sec-policy/selinux-base-policy` pulls the
release distfile. It is not tracked in git. Provenance:

    url:     https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20250213/refpolicy-2.20250213.tar.bz2
    sha512:  cbaf65dfe6d7cc886674bb37160170dac060265d5cf241bfac0c0e5ef45744f057107d81c933f01411c5cd538c95755b7a92331197e2b97b995efc4d6f266895
    blake2b: 64d64549bf1fcfc33107e8f4c842af4e3279a856c3a140d05749bae687ffadfe25e4b7383bef3618b13bbd553046d162fcd48b7135003fd59073b5bece91008

Both hashes are on the `DIST refpolicy-2.20250213.tar.bz2` line of
`selinux-desktop-system/Manifest`.

## Language: CIL or TE?

Both work here, and the choice is real.

What the eclass supports: `MODS`/`POLICY_FILES` accept either. The refpolicy
build Makefile only globs `*.te`, so a `.cil` is not *compiled* - but the
eclass has a pass-through branch that copies it, and `semodule -i` accepts CIL
natively. Verified: `ebuild ... install` puts `desktop.system.cil` and
`desktop.system.users.cil` into the image, and the box runs those two modules
alongside the refpolicy ones.

So depending on refpolicy does **not** force your own modules to be TE.
refpolicy is the base policy and its interface library; your modules may be
CIL, and two already are.

**CIL** - one file per module instead of a `.te`/`.if`/`.fc` trio (file
contexts are `(filecon ...)`), no m4, and it is the language libsemanage
stores, so store -> source is near-lossless. Cost: the interface library is m4
and therefore unavailable, rules must be spelled out, and with `secilc` not
installed a bad `.cil` only surfaces at `semodule -i` time.

**TE** - you keep refpolicy's macros (`dev_read_generic_files`, `corenet_*`,
`kernel_getattr_proc`, ...) and the hand-written per-rule provenance comments,
which is where much of this policy's value sits.

The trap worth knowing: a recovered `.cil` is the *expanded* form, so it is the
residue of macro expansion, and re-macroing a module is a **re-design, not a
round-trip**. Writing `ssh_t user_home_t:dir search` as the interface that
grants it grants that interface's full documented access - a different rule
set, often a better one, but a policy change. It has to be verified by diffing
the compiled rule set against the CIL, never assumed.

Current choice: the two recovered modules ship as CIL (they have no macro
history left to preserve); the hand-written modules stay TE. `tools/` is empty
of a converter on purpose - see git history for the CIL->TE experiment.

## The network half

The point of the exercise, and half-built. `ruleset.nftables` is **live** - it
labels packets with SELinux secmarks by protocol, port and direction - the
packet types exist in the policy, and that labelling is already producing real
`packet` denials (59 of them, in `captures/`). What is missing is the SELinux
side: the per-tier network domains are inert and nothing grants domains the
packet labels their traffic carries.

Full status, the denial breakdown and the wiring order: **`wip/README.md`**.

## Known issues

- `desktop.system.users` is inert: no `stem_u`/`branch_u`/`leaf_u` SELinux user
  exists, `seusers` maps those accounts to `sysadm_u`/`staff_u`/`user_u`, and
  the tier `*_file_type` attributes are declared with nothing ever attached to
  them. 8652 lines of policy no login can enter.
- The secmark maps cover only ports 22/53/80/443, so every other flow (mosh on
  60001/60002, and anything else) is unlabelled and hits `unlabeled_t`. That is
  a design decision to make, not a bug to patch - see `wip/README.md`.
- The deployed `/var/lib/nftables/rules-save` is one revision behind
  `files/ruleset.nftables`: it is missing the four `iif lo` rules.
- `desktop.system.base.te` mixes `allow` and `dontaudit` for the same class of
  inherited-fd rule. Four provably dead `dontaudit`s - fully shadowed by an
  identical `allow` in the same compiled policy - were removed; the rest are
  consistent.
