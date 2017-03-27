from itertools import chain


def asc_seq(maxlen):
    # %timeit -n 1000 list(map(list, asc_seq(10)))
    # 1000 loops, best of 3: 3.04 ms per loop
    assert maxlen >= 0

    def g(seq):
        yield seq
        if len(seq) < maxlen:
            g1 = g(seq + [seq[-1]])
            g2 = g(seq + [seq[-1] + 1])
            while True:
                try:
                    yield next(g1)
                    yield next(g2)
                except StopIteration:
                    break

    yield []
    if maxlen > 0:
        yield from g([0])


def group_asc_seq(seq):
    ans = []
    cur = -1
    count = None
    for n in chain(seq, [-2]):
        if n != cur:
            ans.append(count)
            cur = n
            count = 1
        else:
            count += 1

    return ans[1:]


def perm2(grp1, grp2, cls1=True, cls2=False):
    buf = []

    def g(grp1, grp2):
        if grp1 == 0:
            buf.extend([cls2] * grp2)
            yield buf
            del buf[-grp2:]
        elif grp2 == 0:
            buf.extend([cls1] * grp1)
            yield buf
            del buf[-grp1:]
        else:
            buf.append(cls1)
            yield from g(grp1 - 1, grp2)
            buf.pop()

            buf.append(cls2)
            yield from g(grp1, grp2 - 1)
            buf.pop()

    yield from g(grp1, grp2)


def fill(buf, elem, pattern):
    cur = 0
    for p in pattern:
        while buf[cur] is not None:
            cur += 1
        if p:
            buf[cur] = elem
        cur += 1


def unfill(buf, elem):
    for i in range(len(buf)):
        if buf[i] == elem:
            buf[i] = None


def perm_seq(seq):
    group = group_asc_seq(seq)
    total = sum(group)
    buf = [None] * total

    def g(cur, remain):
        grp1 = group[cur]
        grp2 = remain - grp1
        for pattern in perm2(grp1, grp2):
            fill(buf, cur, pattern)
            if grp2 == 0:
                yield buf
            else:
                yield from g(cur + 1, grp2)
            unfill(buf, cur)

    if total == 0:
        yield []
    else:
        yield from g(0, total)


def gen_sort_case(maxlen):
    for seq in asc_seq(maxlen):
        yield from perm_seq(seq)
