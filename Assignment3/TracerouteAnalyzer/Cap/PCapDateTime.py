import datetime
from decimal import Decimal


class PCapDateTime:
    def __init__(self, timestamp, calculated=False):
        # I found that the ns flag is no use, so just treat them as the same.
        if isinstance(timestamp, PCapDateTime):
            self.__source_ts = round(timestamp.get_source_ts(), 6)
        elif isinstance(timestamp, Decimal):
            self.__source_ts = round(timestamp, 6)
        else:
            self.__source_ts = round(Decimal(timestamp), 6)
        self.__calculated = calculated

    def __sub__(self, other):
        if isinstance(other, PCapDateTime):
            return PCapDateTime(self.get_source_ts() - other.get_source_ts(), calculated=True)
        else:
            return PCapDateTime(self.get_source_ts() - Decimal(other), calculated=True)

    def __add__(self, other):
        if isinstance(other, PCapDateTime):
            return PCapDateTime(self.get_source_ts() + other.get_source_ts(), calculated=True)
        else:
            return PCapDateTime(self.get_source_ts() + Decimal(other), calculated=True)

    def __rsub__(self, other):
        return PCapDateTime(self.get_source_ts() - other, calculated=True)

    def __radd__(self, other):
        return PCapDateTime(self.get_source_ts() + other, calculated=True)

    def __eq__(self, other):
        return self.get_source_ts() == other.get_source_ts()

    def get_source_ts(self):
        return self.__source_ts

    def __hash__(self):
        return hash(self.get_source_ts())

    def __lt__(self, other):
        if isinstance(other, PCapDateTime):
            return self.get_source_ts() < other.get_source_ts()
        else:
            return self.get_source_ts() < Decimal(other)

    def __gt__(self, other):
        if isinstance(other, PCapDateTime):
            return self.get_source_ts() > other.get_source_ts()
        else:
            return self.get_source_ts() > Decimal(other)

    def __le__(self, other):
        if isinstance(other, PCapDateTime):
            return self.get_source_ts() <= other.get_source_ts()
        else:
            return self.get_source_ts() <= Decimal(other)

    def __ge__(self, other):
        if isinstance(other, PCapDateTime):
            return self.get_source_ts() >= other.get_source_ts()
        else:
            return self.get_source_ts() >= Decimal(other)

    def __truediv__(self, other):
        return PCapDateTime("{:.6f}".format(self.get_source_ts() / Decimal(other)), calculated=True)

    def __abs__(self):
        return PCapDateTime(abs(self.get_source_ts()), calculated=True)

    def sqrt(self):
        return PCapDateTime("{:.6f}".format(Decimal.sqrt(abs(self.get_source_ts() * pow(10, 4))) / pow(10, 2)),
                            calculated=True)

    def __str__(self):
        try:
            __int, __decimal = str(self.get_source_ts()).split(".")
        except:
            __int, __decimal = str(str(self.get_source_ts()) + ".000000000").split(".")
        if self.__calculated:
            try:
                __int = int(__int)
            except:
                __int = Decimal(__int).to_integral_value()
            return (("{} s, ".format(Decimal(__int).to_integral_value()) if __int != Decimal(
                0) else "") + "{:.1f} ms".format(Decimal(__decimal) / pow(10, 3)))
        else:
            try:
                __int = int(__int)
            except:
                __int = Decimal(__int).to_integral_value()
            return datetime.datetime.fromtimestamp(__int).strftime(
                "%Y-%m-%d %H:%M:%S") + ", {:.1f} ms".format(Decimal(__decimal) / pow(10, 3))
