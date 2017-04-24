# Search algorithm utility
import bisect


def ternary_search(lo, hi, f):
    if lo == hi:
        return lo
    m1 = (lo + hi) // 3
    m2 = (2 * (lo + hi)) // 3
    if f(m1) < f(m2):
        return ternary_search(m1, hi, f)
    return ternary_search(lo, m2, f)
