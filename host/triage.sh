#!/usr/bin/env bash
#
# triage.sh - first-ten-minutes evidence grab from a Linux box you think is popped.
#
#   sudo ./triage.sh -o /mnt/usb
#   sudo ./triage.sh -o /mnt/usb -d 3 -q
#
# Collects in rough order of volatility (processes and sockets first, files
# on disk last), logs every command it ran with its exit status, hashes
# everything, and tars it up. Read-only apart from the output directory.
#
# Write the output somewhere that is NOT the disk you might image later.
# Use trusted binaries if you have them: PATH=/mnt/usb/bin:$PATH ./triage.sh
#
# This is triage, not forensics. It tells you whether to pull the box and
# where to look. It does not replace a memory capture or a disk image.

set -u
set -o pipefail
export LC_ALL=C
umask 077

OUT=.
DAYS=7
QUICK=0
TAR=1
CMD_TIMEOUT=60

usage() {
    sed -n '3,6p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

  -o DIR    where to write (default: current directory)
  -d DAYS   how far back "recently modified" goes (default: $DAYS)
  -q        quick: skip the filesystem walks and package verification
  -n        leave the directory, don't tar it
  -h        this
EOF
    exit "${1:-0}"
}

while getopts "o:d:qnh" opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        d) DAYS=$OPTARG ;;
        q) QUICK=1 ;;
        n) TAR=0 ;;
        h) usage 0 ;;
        *) usage 2 >&2 ;;
    esac
done

case $DAYS in ''|*[!0-9]*) echo "triage: -d wants a number" >&2; exit 2 ;; esac
[ -d "$OUT" ] && [ -w "$OUT" ] || { echo "triage: can't write to $OUT" >&2; exit 2; }

HOST=$(hostname -s 2>/dev/null || cat /proc/sys/kernel/hostname)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="triage-$HOST-$STAMP"
DIR="$OUT/$NAME"
LOG="$DIR/collection.log"
mkdir -p "$DIR" || exit 2

if [ "$(id -u)" -ne 0 ]; then
    echo "triage: not root, expect gaps (other users' procs, shadow, sockets)" >&2
fi

note() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" >>"$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }

# run <outfile> <command...>
# One file per command so a truncated or hung collector only costs that file.
run() {
    local out="$DIR/$1" rc; shift
    mkdir -p "$(dirname "$out")"
    if ! have "$1"; then
        note "SKIP (not installed): $*"
        return 0
    fi
    if have timeout; then
        timeout "$CMD_TIMEOUT" "$@" >"$out" 2>"$out.err"
    else
        "$@" >"$out" 2>"$out.err"
    fi
    rc=$?
    [ -s "$out.err" ] || rm -f "$out.err"
    # squash the multi-line snippets so the log stays one line per command
    note "rc=$rc  $(printf '%s ' "$@" | tr -s '\n ' ' ' | cut -c1-200)"
}

# sh_run <outfile> <shell snippet>, for pipelines and globs
sh_run() {
    local out=$1; shift
    run "$out" bash -c "$*"
}

# copy a file in, keeping its timestamps
grab() {
    local src=$1 dest="$DIR/files$1"
    [ -e "$src" ] || return 0
    mkdir -p "$(dirname "$dest")"
    if cp -p --no-dereference "$src" "$dest" 2>/dev/null; then
        note "copied $src"
    else
        note "FAILED to copy $src"
    fi
}

section() { echo "[*] $1" >&2; note "== $1"; }

note "triage start host=$HOST uid=$(id -u) days=$DAYS quick=$QUICK"
note "collector sha256 $(sha256sum "$0" 2>/dev/null | cut -d' ' -f1)"

# ---------------------------------------------------------------- volatile
section "processes"
run proc/ps_forest.txt ps -eo pid,ppid,user,lstart,tty,stat,pcpu,pmem,args --forest
run proc/ps_wide.txt ps auxwww

# Binary deleted from disk but still running. Malware does this to clean up
# after itself; so does anything that got upgraded and not restarted, so
# check the path before getting excited. A /memfd: path means it was never
# on disk at all.
sh_run proc/deleted_exe.txt '
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case $exe in *" (deleted)") printf "%s\t%s\t%s\n" "${p#/proc/}" "$exe" "$(tr "\0" " " <"$p/cmdline")" ;; esac
done'

# Running out of somewhere world-writable
sh_run proc/exe_in_tmp.txt '
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case $exe in /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*)
        printf "%s\t%s\t%s\n" "${p#/proc/}" "$exe" "$(tr "\0" " " <"$p/cmdline")" ;; esac
done'

# argv[0] is whatever the process wants it to be. comm vs the real exe name
# catches the lazy "[kworker/0:1]" impersonations (kernel threads have no exe).
sh_run proc/fake_kthreads.txt '
for p in /proc/[0-9]*; do
    cmd=$(tr "\0" " " <"$p/cmdline" 2>/dev/null)
    case $cmd in \[*) exe=$(readlink "$p/exe" 2>/dev/null) && printf "%s\t%s\t%s\n" "${p#/proc/}" "$cmd" "$exe" ;; esac
done'

sh_run proc/ld_preload_env.txt '
grep -lz "^LD_PRELOAD=" /proc/[0-9]*/environ 2>/dev/null | while read -r f; do
    p=${f#/proc/}; p=${p%/environ}
    printf "%s\t%s\t%s\n" "$p" "$(tr "\0" "\n" <"$f" | grep "^LD_PRELOAD=")" "$(readlink "/proc/$p/exe")"
done'

section "network"
if have ss; then
    run net/sockets.txt ss -Hantup
    run net/listening.txt ss -Hlntup
else
    run net/sockets.txt netstat -antup
fi
run net/addr.txt ip -details addr
run net/route.txt ip route show table all
run net/neigh.txt ip neigh
run net/resolv.conf cat /etc/resolv.conf
run net/hosts cat /etc/hosts
if have nft; then run net/nft_ruleset.txt nft list ruleset; fi
run net/iptables.txt iptables-save

section "sessions"
run users/w.txt w
run users/who.txt who -a
run users/last.txt last -Faiwx -n 500
run users/lastb.txt lastb -Faiw -n 500
run users/lastlog.txt lastlog

# ---------------------------------------------------------------- system
section "system"
run sys/date.txt date -u
run sys/uname.txt uname -a
run sys/uptime.txt uptime
run sys/os-release cat /etc/os-release
run sys/cmdline cat /proc/cmdline
run sys/mounts.txt cat /proc/mounts
run sys/df.txt df -hT
run sys/lsmod.txt lsmod
# 0 = clean. Anything else means out-of-tree/unsigned modules or similar.
run sys/kernel_tainted cat /proc/sys/kernel/tainted
run sys/dmesg_tail.txt bash -c 'dmesg -T 2>/dev/null | tail -n 300'
run sys/env.txt env

section "accounts"
grab /etc/passwd
grab /etc/group
grab /etc/sudoers
for f in /etc/sudoers.d/*; do grab "$f"; done
sh_run users/uid0.txt "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
sh_run users/login_shells.txt "awk -F: '\$7 !~ /(nologin|false|sync|halt|shutdown)\$/ {print \$1, \$3, \$6, \$7}' /etc/passwd"
# hashes stay on the box. who has a password, and who has none at all, is enough.
sh_run users/shadow_state.txt "awk -F: '{s=\"set\"; if (\$2==\"\") s=\"EMPTY\"; else if (\$2 ~ /^[!*]/) s=\"locked\"; print \$1, s, \"lastchg=\"\$3}' /etc/shadow"

sh_run users/authorized_keys.txt '
while IFS=: read -r user _ _ _ _ home _; do
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        [ -f "$f" ] || continue
        echo "### $user $f  $(stat -c "mtime=%y owner=%U mode=%a" "$f")"
        cat "$f"
    done
done </etc/passwd'
grab /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*; do grab "$f"; done

sh_run users/shell_history.txt '
while IFS=: read -r user _ _ _ _ home _; do
    for f in "$home"/.*_history "$home/.python_history"; do
        [ -f "$f" ] || continue
        echo "### $user $f  $(stat -c "size=%s mtime=%y" "$f")  $( [ -L "$f" ] && echo "SYMLINK -> $(readlink "$f")")"
        tail -n 500 "$f"
    done
done </etc/passwd'

# ---------------------------------------------------------------- persistence
section "persistence"
grab /etc/crontab
grab /etc/anacrontab
grab /etc/rc.local
grab /etc/ld.so.preload          # should basically never exist
grab /etc/environment
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
         /var/spool/cron /var/spool/cron/crontabs /var/spool/at /etc/profile.d \
         /etc/systemd/system /etc/udev/rules.d /etc/xdg/autostart; do
    [ -d "$d" ] || continue
    run "persist/ls$(echo "$d" | tr / _).txt" ls -la --time-style=full-iso "$d"
    find "$d" -maxdepth 2 -type f -size -256k 2>/dev/null | while read -r f; do grab "$f"; done
done

if have systemctl; then
    run persist/systemd_units.txt systemctl list-unit-files --no-pager
    run persist/systemd_running.txt systemctl list-units --type=service --state=running --no-pager
    run persist/systemd_timers.txt systemctl list-timers --all --no-pager
    # units that didn't come from a package are the interesting ones
    sh_run persist/systemd_recent.txt "find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd -type f \
        \\( -name '*.service' -o -name '*.timer' -o -name '*.socket' \\) -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort"
fi

sh_run persist/user_rc_files.txt '
while IFS=: read -r user _ _ _ _ home _; do
    for f in .bashrc .bash_profile .profile .zshrc .bash_logout .config/autostart .config/systemd/user; do
        [ -e "$home/$f" ] && stat -c "%y  %U  %n" "$home/$f"
    done
done </etc/passwd | sort -r'

# ---------------------------------------------------------------- filesystem
if [ "$QUICK" -eq 0 ]; then
    section "filesystem (slow, -q skips)"
    CMD_TIMEOUT=600

    # -xdev keeps find off nfs, proc, and whatever else is mounted
    sh_run fs/suid_sgid.txt "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f \
        -printf '%M %u:%g %TY-%Tm-%Td %p\n' 2>/dev/null | sort -k4"

    sh_run fs/recent_system_files.txt "find /etc /usr/bin /usr/sbin /usr/local /bin /sbin /lib/modules /root /home -xdev \
        -type f -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM  %M %u  %s  %p\n' 2>/dev/null | sort -r | head -n 5000"

    # ctime moves on chmod/chown/rename and can't be set back with touch.
    # mtime older than ctime by a lot, on a binary, is worth a second look.
    sh_run fs/ctime_newer_than_mtime.txt "find /usr/bin /usr/sbin /bin /sbin /usr/local/bin -xdev -type f -ctime -$DAYS -mtime +$DAYS \
        -printf 'c=%CY-%Cm-%Cd m=%TY-%Tm-%Td  %p\n' 2>/dev/null"

    sh_run fs/tmp_listing.txt "find /tmp /var/tmp /dev/shm -xdev -printf '%TY-%Tm-%Td %TH:%TM  %M %u  %s  %p\n' 2>/dev/null | sort -r | head -n 5000"
    sh_run fs/tmp_executables.txt "find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -exec sha256sum {} + 2>/dev/null"
    sh_run fs/hidden_dirs.txt "find / -xdev -type d \\( -name '.. *' -o -name '...' -o -name '. *' -o -name ' *' \\) 2>/dev/null"

    section "package verification"
    if have dpkg; then
        run pkg/dpkg_verify.txt dpkg --verify
        run pkg/dpkg_list.txt dpkg -l
    elif have rpm; then
        run pkg/rpm_verify.txt rpm -Va --nomtime
        run pkg/rpm_list.txt rpm -qa --last
    fi
else
    note "quick mode: skipped filesystem walks and package verification"
fi

# ---------------------------------------------------------------- logs
section "logs"
for f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure-* \
         /var/log/audit/audit.log /var/log/syslog /var/log/messages /var/log/kern.log \
         /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/dpkg.log /var/log/yum.log /var/log/dnf.log; do
    # 200M cap. If audit.log is bigger than that, go get it deliberately.
    [ -f "$f" ] && [ "$(stat -c %s "$f")" -lt 209715200 ] && grab "$f"
done
if have journalctl; then
    run logs/journal_since.txt journalctl --no-pager -o short-iso --since "-${DAYS}d" -p warning
    run logs/journal_ssh.txt journalctl --no-pager -o short-iso --since "-${DAYS}d" -t sshd -t sshd-session -t sudo -t su
fi

# ---------------------------------------------------------------- wrap up
section "hashing"
note "triage end"
( cd "$DIR" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum >MANIFEST.sha256 )

flag() { [ -s "$DIR/$1" ] && echo "    !! $2: $(wc -l <"$DIR/$1") (see $1)"; }
echo >&2
echo "[*] worth a look first:" >&2
{
    flag proc/deleted_exe.txt     "processes running a deleted binary"
    flag proc/exe_in_tmp.txt      "processes running from tmp/shm"
    flag proc/fake_kthreads.txt   "userland processes dressed as kernel threads"
    flag proc/ld_preload_env.txt  "processes with LD_PRELOAD set"
    [ -e "$DIR/files/etc/ld.so.preload" ] && echo "    !! /etc/ld.so.preload exists"
    [ -s "$DIR/users/uid0.txt" ] && [ "$(wc -l <"$DIR/users/uid0.txt")" -gt 1 ] && echo "    !! more than one uid 0 account"
    grep -q EMPTY "$DIR/users/shadow_state.txt" 2>/dev/null && echo "    !! account(s) with an empty password"
    flag fs/tmp_executables.txt   "executables sitting in tmp/shm"
    flag fs/hidden_dirs.txt       "oddly named directories"
    true
} >&2

if [ "$TAR" -eq 1 ]; then
    tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME" && rm -rf "$DIR"
    echo >&2
    # write this hash down somewhere that isn't this machine
    ( cd "$OUT" && sha256sum "$NAME.tar.gz" )
else
    echo "$DIR"
fi
