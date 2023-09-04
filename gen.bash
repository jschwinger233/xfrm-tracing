head=$(cat /proc/kallsyms | awk '$2 ~ /t/ {print $1}' | sort  | head -1)
tail=$(cat /proc/kallsyms | awk '$2 ~ /t/ {print $1}' | sort  | tail -1)
diff=$((0x$tail - 0x$head))
gdb -ex "x/${diff}i 0x$head" -ex q /proc/kcore /proc/kcore | python3 filter_xfrm_inc_asm.py  > xfrm_inc_ctx.yaml
