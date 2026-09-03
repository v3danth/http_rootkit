#!/usr/bin/env bash
# IOC (spec §11.3 / F-34): /sys/module entry with no /proc/modules line
# (classic list_del module hiding). False positives: /sys/module also
# contains built-in (=y) components — filter the common ones or keep a
# per-host baseline.
BUILTINS='acpi|bluetooth|cfg80211|efivarfs|ipv6|kernel|md_mod|net|printk|rcupdate|scsi_mod|tcp_congestion|tun|udp|wmi'
ls /sys/module | sort > /tmp/.sctg_a
awk '{print $1}' /proc/modules | sort > /tmp/.sctg_b
echo "== in /sys/module but not /proc/modules =="
comm -23 /tmp/.sctg_a /tmp/.sctg_b | grep -Ev "^($BUILTINS)$"
echo "== /proc/modules count: $(wc -l < /tmp/.sctg_b) =="
rm -f /tmp/.sctg_a /tmp/.sctg_b
