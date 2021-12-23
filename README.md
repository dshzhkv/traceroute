# traceroute
Утилита traceroute с возможностью отправки пакетов по ICMP, TCP или UDP.

usage:

`traceroute.py [OPTIONS] IP_ADDRESS {tcp|udp|icmp}`

Опции `[OPTIONS]` следующие:

* `-t, --timeout` — таймаут ожидания ответа (по умолчанию 2с)
* `-p, --port` — порт (для tcp или udp)
* `-n, --num_of_requests` — максимальное количество запросов
* `-v, --show_system_num` — вывод номера автономной системы для каждого ip-адреса


example (Windows):
`python traceroute.py -p 53 1.1.1.1 tcp`
