#!/bin/sh

DATE="$1"
NAME="$2"
shift 2
ausearch -m avc,user_avc,selinux_err,user_selinux_err -ts $(date --date="$DATE" +"%H:%M:%S") $@ | tee $NAME.audit | audit2allow -Revl | tee $NAME.te | less +F
