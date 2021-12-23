import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP, ICMP, TCP
import ipwhois


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--timeout', type=int, default=2,
                        help='таймаут ожидания ответа (по умолчанию 2с)')
    parser.add_argument('-p', '--port', type=int, default=53,
                        help='подробный')
    parser.add_argument('-n', '--num_of_requests', type=int, default=5,
                        help='максимальное количество запросов')
    parser.add_argument('-v', '--show_system_num', action="store_true",
                        default=False, help='вывод номера автономной системы '
                                            'для каждого ip-адреса')

    parser.add_argument("IP_ADDRESS", type=str, help='ip адрес')

    parser.add_argument('connection_type', type=str, help='{tcp|udp|icmp}')

    args = parser.parse_args()

    return args


def get_system_num(ip):
    try:
        reply = ipwhois.IPWhois(ip)
    except ipwhois.exceptions.IPDefinedError:
        return '---'
    return reply.lookup_whois()['asn']


def get_record(num, ip, _time, show_system_num, timeout=False):
    if timeout:
        if show_system_num:
            return '{}  *  *  *  TIMEOUT'.format(num)
        else:
            return '{}  *  *  TIMEOUT'.format(num)

    if show_system_num:
        system_num = get_system_num(ip)
        return '{}  {}  {} ms  {}'.format(num, ip, round(_time, 3), system_num)
    return '{}  {}  {} ms'.format(num, ip, round(_time, 3))


def trace(args):
    for i in range(1, args.num_of_requests + 1):
        result = get_reply(i, args)

        if result is None:
            print('Unknown protocol')
            break

        reply, _time = result

        if reply is None:
            print(get_record(i, None, _time, args.show_system_num, True))
            continue

        print(get_record(i, reply.src, _time, args.show_system_num))

        if reply.src == args.IP_ADDRESS:
            break


def get_reply(i, args):
    time_start = time.perf_counter()
    if args.connection_type == 'tcp':
        data = IP(dst=args.IP_ADDRESS, ttl=i) / TCP(dport=args.port)
    elif args.connection_type == 'udp':
        data = IP(dst=args.IP_ADDRESS, ttl=i) / UDP(dport=args.port)
    elif args.connection_type == 'icmp':
        data = IP(dst=args.IP_ADDRESS, ttl=i) / ICMP()
    else:
        return None
    reply = sr1(data, verbose=0, timeout=args.timeout)
    time_stop = time.perf_counter()
    return reply, time_stop - time_start


def main():
    trace(get_args())


if __name__ == '__main__':
    main()
