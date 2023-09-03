import re
import fileinput

pat = re.compile(
    r"0x(?P<address>[0-9a-f]+):\s+incq\s+%gs:0x(?P<offset>[0-9a-f]+)\(%(?P<reg>[a-z]+)\)"
)

for line in fileinput.input():
    match = pat.search(line)
    if not match:
        continue
    offset = int(match.group("offset"), 16)
    if offset % 8 != 0 or offset > 28 * 8:
        continue
    address = int(match.group("address"), 16)
    reg = match.group("reg")
    print(f'''
- address: {address} # 0x{address:x}
  register: {reg}
  xfrm_stat_index: {offset//8} # 0x{offset:x}''')
