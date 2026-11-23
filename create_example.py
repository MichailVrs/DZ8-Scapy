import gzip
from scapy.all import Ether, IP, TCP, Raw, wrpcap

frames = []
for i, name in enumerate(("Anna", "LAB8-42")):
    client, server = "192.0.2.10", "192.0.2.20"
    port = 49152 + i
    form = b"name=LAB8-42"
    if i == 0:
        request = b"GET /hello?name=Anna HTTP/1.1\r\nHost: lab.example:8000\r\n\r\n"
    else:
        request = (b"POST /hello HTTP/1.1\r\nHost: lab.example:8000\r\n"
                   b"Content-Type: application/x-www-form-urlencoded\r\n"
                   + f"Content-Length: {len(form)}\r\n\r\n".encode() + form)
    html = f"<p>Hello, {name}!</p>".encode()
    compressed = gzip.compress(html, mtime=0)
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                b"Content-Encoding: gzip\r\n"
                + f"Content-Length: {len(compressed)}\r\n\r\n".encode() + compressed)
    for src, dst, sp, dp, seq, data in (
        (client, server, port, 8000, 100, request),
        (server, client, 8000, port, 200, response[:-10]),
        (server, client, 8000, port, 200 + len(response) - 10, response[-10:]),
    ):
        frames.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                      IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, seq=seq, flags="PA") / Raw(data))
wrpcap("DZ8.pcap", frames)
