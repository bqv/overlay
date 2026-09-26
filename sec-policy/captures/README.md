# captures

Raw evidence from `../aud.sh`: one `<date>-<name>.audit` per capture, plus the
`audit2allow` first draft as `<date>-<name>.te`. The date is the timestamp of
the first AVC in the dump, not the file mtime.

These are **not build input** and are not in git (see `/.gitignore`). They are
the baseline you diff a later boot against. A rule gets triaged out of here and
into `selinux-desktop-home/files/` or `selinux-desktop-system/files/` by hand,
annotated with the app that caused it.

| date | capture |
|---|---|
| 2025-08-31 | boot, ipcrm, runcon, swapon, xapp |
| 2025-09-01 | bindfs, psi, psi-plus |
| 2025-09-02 | mosh, mozilla |
| 2025-09-04 | usbaudio |
| 2025-09-07 | git |
| 2025-09-08 | psi-mozilla |
