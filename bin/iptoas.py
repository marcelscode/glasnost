#!/usr/bin/python
import sys

# This uses data collected by the iPlane project

MASK = {
0 :~0xFFFFFFFF,
1 :~0x7FFFFFFF,
2 :~0x3FFFFFFF,
3 :~0x1FFFFFFF,
4 :~0x0FFFFFFF,
5 :~0x07FFFFFF,
6 :~0x03FFFFFF,
7 :~0x01FFFFFF,
8 :~0x00FFFFFF,
9 :~0x007FFFFF,
10:~0x003FFFFF,
11:~0x001FFFFF,
12:~0x000FFFFF,
13:~0x0007FFFF,
14:~0x0003FFFF,
15:~0x0001FFFF,
16:~0x0000FFFF,
17:~0x00007FFF,
18:~0x00003FFF,
19:~0x00001FFF,
20:~0x00000FFF,
21:~0x000007FF,
22:~0x000003FF,
23:~0x000001FF,
24:~0x000000FF,
25:~0x0000007F,
26:~0x0000003F,
27:~0x0000001F,
28:~0x0000000F,
29:~0x00000007,
30:~0x00000003,
31:~0x00000001,
32:~0x00000000,
}

MAP = dict([(x, dict()) for x in xrange(33)])

for line in open("as_map", "r"):
    toks = line[:-1].replace("/", ".").replace(" ", ".").split(".")
    ip_a = int(toks[0])
    ip_b = int(toks[1])
    ip_c = int(toks[2])
    ip_d = int(toks[3])
    mask = int(toks[4])
    asnum = toks[5]
    ip = ip_a << 24 | ip_b << 16 | ip_c << 8 | ip_d
    MAP[mask][ip & MASK[mask]] = asnum

for line in sys.stdin:
    toks = line[:-1].split(".")
    ip_a = int(toks[0])
    ip_b = int(toks[1])
    ip_c = int(toks[2])
    ip_d = int(toks[3])
    ip = ip_a << 24 | ip_b << 16 | ip_c << 8 | ip_d
    for mask in xrange(32, -1, -1):
        ipm = ip & MASK[mask]
        if ipm in MAP[mask]:
            print line[:-1], MAP[mask][ipm]
            break
