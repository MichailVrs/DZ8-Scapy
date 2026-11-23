"""В PyCharm запусти этот файл кнопкой Run."""
from datetime import datetime
from pathlib import Path
import subprocess
from threading import Event
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from scapy.all import AsyncSniffer, PcapWriter, conf
from http_report import save_report

PROJECT = Path(__file__).resolve().parent
EXAMPLE = PROJECT / "DZ8.pcap"
PORT = 8008
RULE = f"host 127.0.0.1 and tcp port {PORT}"


class App:
    def __init__(self, window):
        self.window = window
        window.title("ДЗ 8 · Запись и анализ HTTP")
        panel = ttk.Frame(window, padding=16)
        panel.pack(fill="both", expand=True)
        self.server = None
        self.sniffer = None
        self.writer = None
        self.path = None
        self.ready = Event()
        self.interfaces = sorted(conf.ifaces.values(), key=lambda dev: dev.index)
        labels = [f"{d.index} · {d.description or d.name} · {d.ip}" for d in self.interfaces]
        ttk.Label(panel, text="Интерфейс для локального Gruyere (127.0.0.1:8008)").pack(anchor="w")
        self.interface = ttk.Combobox(panel, values=labels, state="readonly", width=64)
        self.interface.pack(fill="x", pady=(3, 10))
        if labels:
            default = next((i for i, d in enumerate(self.interfaces) if d.ip == "127.0.0.1"), 0)
            self.interface.current(default)
        ttk.Button(panel, text="Запустить локальный Gruyere…", command=self.start_server).pack(fill="x")
        self.start = ttk.Button(panel, text="Начать запись", command=self.start_capture)
        self.start.pack(fill="x", pady=(8, 2))
        self.stop = ttk.Button(panel, text="Остановить и открыть отчёт", command=self.finish_capture,
                               state="disabled")
        self.stop.pack(fill="x")
        ttk.Button(panel, text="Открыть учебный отчёт", command=lambda: self.report(EXAMPLE, 8000)).pack(fill="x", pady=(8, 2))
        ttk.Button(panel, text="Разобрать запись Gruyere…", command=self.choose_capture).pack(fill="x")
        self.status = tk.StringVar(value="Готово к работе.")
        ttk.Label(panel, textvariable=self.status, wraplength=500).pack(anchor="w", pady=(10, 0))
        window.protocol("WM_DELETE_WINDOW", self.close)

    def start_server(self):
        if self.server and self.server.poll() is None:
            webbrowser.open("http://127.0.0.1:8008/")
            return
        script = filedialog.askopenfilename(title="Выбери gruyere.py из распакованного стенда",
                                            filetypes=[("Сервер Gruyere", "gruyere.py")])
        if not script:
            return
        try:
            self.server = subprocess.Popen(["py", "-2.7", script], cwd=Path(script).parent)
        except OSError as error:
            messagebox.showerror("Запуск Gruyere", f"Нужен Python 2.7 с Windows Launcher (py).\n{error}")
            return
        self.window.after(1500, self.open_server)

    def open_server(self):
        if self.server.poll() is None:
            webbrowser.open("http://127.0.0.1:8008/")
        else:
            messagebox.showerror("Запуск Gruyere", "Сервер завершился. Проверь Python 2.7 и сообщение в панели Run.")

    def start_capture(self):
        index = self.interface.current()
        if index < 0:
            messagebox.showerror("Интерфейс", "Выбери интерфейс Npcap для записи.")
            return
        self.ready.clear()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.path = PROJECT / f"Вражевских_Михаил_ДЗ8_{stamp}.pcap"
        try:
            self.writer = PcapWriter(self.path.open("xb"), sync=True)
            self.sniffer = AsyncSniffer(iface=self.interfaces[index], filter=RULE, store=False,
                                        prn=self.writer.write, started_callback=self.ready.set)
            self.sniffer.start()
        except Exception as error:
            self.finish_capture(error=error)
            return
        self.start.configure(state="disabled")
        self.interface.configure(state="disabled")
        self.status.set("Открываю интерфейс…")
        self.window.after(150, self.poll_capture)

    def poll_capture(self):
        if self.sniffer is None:
            return
        if not self.sniffer.thread.is_alive():
            self.finish_capture(error=self.sniffer.exception or RuntimeError("Захват прерван."))
            return
        if self.ready.is_set():
            self.status.set(f"Идёт запись в {self.path.name}. Выполни действие в браузере.")
            self.stop.configure(state="normal")
        self.window.after(250, self.poll_capture)

    def finish_capture(self, error=None, open_report=True):
        sniffer, self.sniffer = self.sniffer, None
        try:
            if sniffer and sniffer.running and self.ready.is_set():
                sniffer.stop()
        except Exception as stop_error:
            error = error or stop_error
        finally:
            if self.writer:
                self.writer.close()
                self.writer = None
        self.stop.configure(state="disabled")
        self.start.configure(state="normal")
        self.interface.configure(state="readonly")
        if error:
            self.status.set("Запись прервана.")
            messagebox.showerror("Захват трафика", f"{error}\n\nЕсли Npcap сообщает Admin-only Mode, "
                                 "открой PyCharm от имени администратора и повтори запись.")
        elif self.path.stat().st_size <= 24:
            self.status.set("Пакетов нет. Проверь интерфейс и адрес локального стенда (порт 8008).")
        elif open_report:
            self.report(self.path, PORT)

    def choose_capture(self):
        path = filedialog.askopenfilename(initialdir=PROJECT, filetypes=[("Запись трафика", "*.pcap")])
        if path:
            self.report(Path(path), PORT)

    def report(self, path, port):
        try:
            output = save_report(path, port)
            webbrowser.open(output.as_uri())
            self.status.set(f"Отчёт сохранён: {output.name}")
        except Exception as error:
            messagebox.showerror("Чтение записи", str(error))

    def close(self):
        if self.sniffer:
            if not self.ready.is_set() and self.sniffer.thread.is_alive():
                self.status.set("Дождись открытия интерфейса.")
                return
            self.finish_capture(open_report=False)
        if self.server and self.server.poll() is None:
            self.server.terminate()
        self.window.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
