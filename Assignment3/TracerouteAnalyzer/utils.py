import warnings


def int_to_ipv6(ip: tuple):
    """
    Convert integer tuple to IPv6 address string. Like fd12:3456:7890::1.

    :param ip: IPv6 address in integer.
    :return: IPv6 string.
    """
    __return_ip = ""
    for i in range(len(ip)):
        if i == 0:
            __return_ip += hex(ip[i])[2:] + ":"
            continue
        if ip[i] == 0 and ip[i - 1] == 0:
            continue
        if ip[i] == 0:
            __return_ip += ":"
            continue
        __return_ip += hex(ip[i])[2:] + ":"
    return __return_ip[:-1]


def int_to_ipv4(ip: int):
    """
    Convert integer to IPv4 address string. Like 10.24.0.1.

    :param ip: IPv4 in integer.
    :return: IPv4 string.
    """
    return "{}.{}.{}.{}".format(ip >> 24, (ip & 0x00ffffff) >> 16, (ip & 0x0000ffff) >> 8, (ip & 0x000000ff))


def deprecated(message):
    def deprecated_decorator(func):
        def deprecated_func(*args, **kwargs):
            warnings.warn("{} is a deprecated function. {}".format(func.__name__, message),
                          category=DeprecationWarning,
                          stacklevel=2)
            warnings.simplefilter('default', DeprecationWarning)
            return func(*args, **kwargs)

        return deprecated_func

    return deprecated_decorator


@deprecated("Shouldn't be used.")
def TCPIPWrapper(link_type: str, ip_header) -> tuple or None:
    """
    Whatever IPv4 or IPv6 the ip_header is, just judge if it is TCP/IP packet and create TCP/IP object.

    :param link_type: IPv4 or IPv6 or something.
    :param ip_header: Raw IP header.
    :return: Tuple of IP object and TCP object.
    """
    try:
        from Cap.NetworkLayer import IPv4, IPv6
        if link_type == "IPv4":
            __temp_ip = IPv4(ip_header)
        elif link_type == "IPv6":
            __temp_ip = IPv6(ip_header)
        else:
            # not IP Header, skip
            return None
        if __temp_ip.get_header().protocol != 6:
            # not TCP, pass
            return None
        from Cap.TransportLayer import TCP
        return __temp_ip, TCP(__temp_ip)
    except Exception:
        return None
