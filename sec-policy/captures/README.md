# captures

Raw evidence from `../aud`, which runs the capture/triage pipeline:

    sudo ./aud "2 hours ago" my-capture
    sudo ./aud "2025-09-02 14:00" my-capture

One `<date>-<name>.audit` per capture - the raw `ausearch` output - plus the
`audit2allow` first draft as `<date>-<name>.te`. `<date>` is the day the capture
was taken; the AVC timestamps inside are authoritative.

These are **not build input** and are not in git (see `/.gitignore`). They are
the baseline you diff a later run against. A rule gets triaged out of the draft
into `selinux-desktop-home/files/` or `selinux-desktop-system/files/` by hand,
annotated with the app that caused it.

Dumps are large - a couple of hours of permissive-mode logging was ~37 MB of
`.audit`. Consider `ausearch`'s own filters as `aud`'s trailing arguments.

| date | capture |
|---|---|
| 2025-08-31 | boot, ipcrm, runcon, swapon, xapp |
| 2025-09-01 | bindfs, psi, psi-plus |
| 2025-09-02 | mosh, mozilla |
| 2025-09-04 | usbaudio |
| 2025-09-07 | git |
| 2025-09-08 | psi-mozilla |

## Network denials

`2025-09-02-mosh.audit` and `2025-09-07-git.audit` contain the 59 `packet`-class
denials that the secmark ruleset produces. See `../wip/README.md`.
