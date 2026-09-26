# sec-policy

Hand-written, application-scoped MCS policy for a `staff_u` desktop, layered on
refpolicy 2.20250213 through the `selinux-policy-2` eclass. Built as real
packages in the `local` overlay, not as hand-installed `.pp` files.

## Packages

| package | modules |
|---|---|
| `selinux-desktop-system` | `desktop.system.base`, `desktop.system.mosh` |
| `selinux-desktop-home` | `desktop.home`, `.pipewire`, `.shortwave`, `.firefox`, `.stremio`, `.gajim`, `.crow`, `.openrc` |

`POLICY_TYPES="mcs"`; `selinux-desktop-home` depends on `selinux-desktop-system`.
`desktop.system.base` ships `desktop.system.base.fc` (e.g. `agreety`/`tuigreet`
→ `xdm_exec_t`) and sets the booleans the desktop needs in `pkg_postinst`.

Each app module is a `<name>.fc` / `<name>.if` / `<name>.te` trio under
`<package>/files/`, listed in `MODS` (bare names) and `POLICY_FILES` (with
extensions) in the ebuild.

## Method: denials drive the policy

`./aud.sh <since-HH:MM:SS> <name>` captures AVCs from a point in time:

    ausearch -m avc,user_avc,selinux_err,user_selinux_err -ts <time> \
      | tee <name>.audit | audit2allow -Revl | tee <name>.te

The `.audit` is raw evidence and belongs in `captures/<date>-<name>.audit`
(see `captures/README.md`); the `.te` is an `audit2allow` first draft. Neither is
build input - a rule is triaged out of the draft into the module by hand.

Triage conventions, as practised in the existing modules:

- every `allow` is annotated with the app that caused it (`# ckb-next`, `# rofi`)
- rules considered and rejected stay commented, with the reason (`# openrc-user`,
  `# pgrep?`)
- inherited-fd noise (`noatsecure rlimitinh siginh`) becomes `dontaudit`, not `allow`
- audit2allow's boolean hints (`##!!!! This avc can be allowed using...`) are
  recorded but overridden deliberately

## refpolicy

`refpolicy/` is a pristine upstream tree, 2.20250213, kept **for reference only** -
the ebuilds do not read it; `sec-policy/selinux-base-policy` pulls the release
distfile. It is not tracked in git. Provenance:

    url:     https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20250213/refpolicy-2.20250213.tar.bz2
    sha512:  cbaf65dfe6d7cc886674bb37160170dac060265d5cf241bfac0c0e5ef45744f057107d81c933f01411c5cd538c95755b7a92331197e2b97b995efc4d6f266895
    blake2b: 64d64549bf1fcfc33107e8f4c842af4e3279a856c3a140d05749bae687ffadfe25e4b7383bef3618b13bbd553046d162fcd48b7135003fd59073b5bece91008

(both hashes are already recorded on the `DIST refpolicy-2.20250213.tar.bz2` line
of `selinux-desktop-system/Manifest`)

## Known issues

- `audit2allow` currently cannot run: `import selinux` fails under python3.13,
  because the `selinux` bindings are installed for python3.14 only while
  `sepolgen` is installed for python3.13 only. `aud.sh` is unusable until the
  python targets are reconciled.
- `desktop.system.network.te` and `ruleset.nftables` exist in
  `selinux-desktop-system/files/` but are in neither `MODS` nor `POLICY_FILES`,
  so they are not built. They are the stub of the labeled-networking side
  (`sysadm_net_t` / `staff_net_t` / `user_net_t` + nftables `secmark`), and
  nothing maps a domain to those types yet.
- `desktop.system.base.te` mixes `allow` and `dontaudit` for the same class of
  inherited-fd rule (`noatsecure rlimitinh siginh`).
