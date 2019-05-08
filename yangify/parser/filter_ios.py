#!/usr/bin/env python

import re


# from https://github.com/theevilbit/ciscot7/blob/master/ciscot7.py

type7_xlat = [
    0x64,
    0x73,
    0x66,
    0x64,
    0x3B,
    0x6B,
    0x66,
    0x6F,
    0x41,
    0x2C,
    0x2E,
    0x69,
    0x79,
    0x65,
    0x77,
    0x72,
    0x6B,
    0x6C,
    0x64,
    0x4A,
    0x4B,
    0x44,
    0x48,
    0x53,
    0x55,
    0x42,
    0x73,
    0x67,
    0x76,
    0x63,
    0x61,
    0x36,
    0x39,
    0x38,
    0x33,
    0x34,
    0x6E,
    0x63,
    0x78,
    0x76,
    0x39,
    0x38,
    0x37,
    0x33,
    0x32,
    0x35,
    0x34,
    0x6B,
    0x3B,
    0x66,
    0x67,
    0x38,
    0x37,
]


def decrypt_type7(ep):
    dp = ""
    regex = re.compile("(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)")
    result = regex.search(ep)
    s, e = int(result.group(1)), result.group(2)
    for pos in range(0, len(e), 2):
        magic = int(e[pos] + e[pos + 1], 16)
        if s <= 50:
            # xlat length is 51
            newchar = "%c" % (magic ^ type7_xlat[s])
            s += 1
        if s == 51:
            s = 0
        dp += newchar
    return dp


def filter_ios_machine():
    multiline = ""

    def _filter(line):
        nonlocal multiline

        _line = line.lstrip()
        if _line.startswith("!"):
            return None

        if line.endswith("\003"):
            if multiline:
                line = multiline + line
                multiline = ""
                return line
            multiline += line + "\n"
            return None

        if multiline:
            multiline += line + "\n"
            return None

        if _line.startswith("exit-"):
            return None

        type7 = re.match(r"(.*\s+(?:key-string|key|password))\s+7\s+(\w+)(.*)", line)
        if type7:
            line = " ".join(
                [type7.group(1), decrypt_type7(type7.group(2)), type7.group(3)]
            )

        return line

    return _filter


filter_ios = filter_ios_machine()
