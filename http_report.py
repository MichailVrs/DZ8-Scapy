"""Чтение HTTP из pcap и формирование отчёта."""
from email.message import Message
from html import escape
from urllib.parse import parse_qsl, urlsplit

from scapy.all import IP, IPv6, TCP, Raw, sniff
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import bind_bottom_up
from scapy.sessions import TCPSession


def show_message(packet, write=print):
    if HTTPRequest in packet:
        message = packet[HTTPRequest]
    elif HTTPResponse in packet:
        message = packet[HTTPResponse]
    else:
        return

    network = packet[IP] if IP in packet else packet[IPv6]
    title = "Запрос" if isinstance(message, HTTPRequest) else "Ответ"
    write(f"\n{title}   {network.src}:{packet[TCP].sport} → {network.dst}:{packet[TCP].dport}")
    # Выводим только те поля, которые действительно присутствуют в записи.
    if isinstance(message, HTTPRequest):
        first_line = [message.Method, message.Path, message.Http_Version]
    else:
        first_line = [message.Http_Version, message.Status_Code, message.Reason_Phrase]
    write(b" ".join(first_line).decode("iso-8859-1"))
    for field in message.fields_desc[3:]:
        value = message.fields.get(field.name)
        if isinstance(value, bytes):
            write(f"{field.name.replace('_', '-')}: {value.decode('iso-8859-1')}")
        elif isinstance(value, dict):
            for name, raw in value.items():
                write(f"{name.decode('iso-8859-1')}: {raw.decode('iso-8859-1')}")
    if isinstance(message, HTTPRequest):
        target = message.Path.decode("iso-8859-1")
        params = parse_qsl(urlsplit(target).query, keep_blank_values=True)
        write("Параметры URL: " + (", ".join(f"{k} = {v}" for k, v in params) or "нет"))

    # HTTP-слой Scapy уже снимает gzip и chunked при разборе.
    body = message.payload.load if isinstance(message.payload, Raw) else bytes(message.payload)
    if not body:
        write("Тело пустое.")
        return
    metadata = Message()
    metadata["Content-Type"] = (message.Content_Type or b"text/plain").decode("iso-8859-1")
    encoding = metadata.get_content_charset() or "utf-8"
    try:
        content = body.decode(encoding, errors="replace")
    except LookupError:
        content = body.decode("utf-8", errors="replace")
    write("Тело: " + content)
    if metadata.get_content_type() == "application/x-www-form-urlencoded":
        fields = parse_qsl(content, keep_blank_values=True)
        write("Поля формы: " + ", ".join(f"{k} = {v}" for k, v in fields))


def read_report(path, port):
    # Сервер получает запросы на свой порт и отправляет ответы с этого порта.
    bind_bottom_up(TCP, HTTP, dport=port)
    bind_bottom_up(TCP, HTTP, sport=port)
    lines = []

    def add_message(packet):
        show_message(packet, write=lines.append)

    # TCPSession собирает части HTTP-сообщения. Готовые сообщения получает add_message.
    sniff(offline=str(path), session=TCPSession, prn=add_message, store=False)
    if not lines:
        return f"HTTP-сообщений не найдено. Проверь порт {port} и наличие открытого HTTP в записи."
    return "\n".join(lines).lstrip()


def save_report(path, port):
    report = read_report(path, port)
    # escape показывает HTML из пакетов как текст внутри отчёта.
    page = f"""<!doctype html><html lang="ru"><meta charset="utf-8">
    <title>Разбор HTTP</title>
    <style>body{{max-width:84ch;margin:2rem auto;padding:0 1rem;font:16px system-ui}}
    pre{{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.6}}</style>
    <h1>Разбор HTTP</h1><p>{escape(path.name)} · порт {port}</p>
    <pre>{escape(report)}</pre></html>"""
    output = path.with_suffix(".report.html")
    output.write_text(page, encoding="utf-8")
    return output
