import os
import sys
import Cap.Cap as Cap
import Statistic as Statistic

if __name__ == '__main__':
    path = sys.argv[-1]
    # if size over 50MB, which means FULL mode may take too much time.
    if "--instant" not in sys.argv:
        if os.path.getsize(path) >= 50_000_000:
            print("WARNING: File may be too large, use --instant flag to load.")
        instant = False
        c = Cap.Cap(path, instant=instant)
    else:
        instant = True
        c = Cap.Cap(path, instant=instant)
    Statistic.Statistic(c.get_packets(), instant=instant).print()
