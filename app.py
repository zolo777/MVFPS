import sys
import subprocess
import threading
import queue
import socket
import asyncio
import ipaddress
import ctypes
import signal
import time
import struct
from itertools import islice

# Первичная установка зависимостей
def first_run_setup():
    required = ['colorama']
    print("[СИСТЕМА] Проверка зависимостей...")
    
    for package in required:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "show", package],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            print(f"[СИСТЕМА] Установка {package}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print("[СИСТЕМА] Зависимости установлены. Перезапуск...")
                subprocess.call([sys.executable] + sys.argv)
                sys.exit(0)
            except subprocess.CalledProcessError as e:
                print(f"[ОШИБКА] Не удалось установить {package}: {e}")
                sys.exit(1)

first_run_setup()

from colorama import init, Fore, Back, Style
init(autoreset=True)

# Настройки
PORT = 8000
THREADS = 10000
RANGES_FILE = "ranges.txt"
OUTPUT_FILE = "found_ips.txt"
TIMEOUT = 2.5
UPDATE_INTERVAL = 0.1
BATCH_SIZE = 1000000
autoclear_found_on_start = True

# Цветовая схема
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_HEADER = Fore.MAGENTA + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_WARNING = Fore.YELLOW + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_PROGRESS = Fore.BLUE + Style.BRIGHT

# Глобальные переменные
checked_ips = 0
successful_ips = 0
total_ips = 0
queue = queue.Queue()
lock = threading.Lock()
print_lock = threading.Lock()
stop_event = threading.Event()

def print_banner():
    banner = r"""
    ███╗   ███╗██╗   ██╗    ███████╗██████╗ ███████╗
    ████╗ ████║██║   ██║    ██╔════╝██╔══██╗██╔════╝
    ██╔████╔██║██║   ██║    █████╗  ██████╔╝███████╗
    ██║╚██╔╝██║╚██╗ ██╔╝    ██╔══╝  ██╔═══╝ ╚════██║
    ██║ ╚═╝ ██║ ╚████╔╝     ██║     ██║     ███████║
    ╚═╝     ╚═╝  ╚═══╝      ╚═╝     ╚═╝     ╚══════╝
    """
    print(COLOR_HEADER + banner)
    print(COLOR_HEADER + " " * 15 + "MVFastPort Scanner | by Mr_VINIK: https://MrVINIK.t.me/\n")

def update_title():
    title = f"MV FPS | Проверено: {checked_ips}/{total_ips} | Открыто: {successful_ips}"
    if sys.platform == 'win32':
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    else:
        sys.stdout.write(f"\x1b]2;{title}\x07")

def title_updater():
    while not stop_event.is_set():
        with lock:
            update_title()
        stop_event.wait(UPDATE_INTERVAL)

async def async_check_port(ip, port, timeout=TIMEOUT):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=family),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def update_progress():
    progress = checked_ips / total_ips if total_ips > 0 else 0
    failed = checked_ips - successful_ips
    success_percent = (successful_ips / checked_ips) * 100 if checked_ips > 0 else 0
    
    bar = f"{'■' * int(40 * progress):<40}"
    stats = (
        f"Всего: {checked_ips}/{total_ips} | "
        f"Открыто: {successful_ips} | "
        f"Закрыто: {failed} | "
        f"Успех: {success_percent:.2f}%"
    )
    
    line = f"[•] Прогресс: {bar} {stats}"
    padding = " " * max(0, 120 - len(line))
    
    with print_lock:
        sys.stdout.write("\r" + COLOR_PROGRESS + line + padding)
        sys.stdout.flush()

def worker():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while not stop_event.is_set():
        try:
            ip = queue.get_nowait()
            result = loop.run_until_complete(async_check_port(ip, PORT))
            
            with lock:
                global checked_ips, successful_ips
                checked_ips += 1
                if result:
                    successful_ips += 1
                    with open(OUTPUT_FILE, 'a') as f:
                        f.write(f"{ip}\n")
                
                if checked_ips % 50 == 0 or checked_ips == total_ips:
                    update_progress()
                
            queue.task_done()
        except queue.Empty:
            break
    loop.close()

def ipv4_range_to_ips(start, end):
    start_int = struct.unpack("!I", socket.inet_aton(start))[0]
    end_int = struct.unpack("!I", socket.inet_aton(end))[0]
    return (socket.inet_ntoa(struct.pack("!I", i)) for i in range(start_int, end_int + 1))

def batch_generator(generator, batch_size):
    while True:
        batch = list(islice(generator, batch_size))
        if not batch:
            break
        yield batch

def process_range(start_str, end_str):
    if ':' in start_str:
        print(COLOR_WARNING + f"Пропуск IPv6 диапазона: {start_str}-{end_str}")
        return 0
    
    gen = ipv4_range_to_ips(start_str, end_str)
    count = 0
    for batch in batch_generator(gen, BATCH_SIZE):
        for ip in batch:
            queue.put(ip)
        count += len(batch)
    return count

def load_ranges():
    global total_ips
    loaded = 0
    start_time = time.time()
    
    try:
        with open(RANGES_FILE) as f:
            print(COLOR_HEADER + "\n[•] Загрузка диапазонов IP...")
            
            for line_num, line in enumerate(f, 1):
                if stop_event.is_set():
                    break
                
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                if '-' not in line:
                    with print_lock:
                        print(COLOR_WARNING + f"[!] Пропуск некорректной строки {line_num}: {line}")
                    continue
                
                try:
                    start_str, end_str = map(str.strip, line.split('-', 1))
                    count = process_range(start_str, end_str)
                    loaded += count
                    
                    if time.time() - start_time > 1:
                        with print_lock:
                            sys.stdout.write(COLOR_PROGRESS + f"\r[•] Загружено {loaded:,} IP")
                            sys.stdout.flush()
                    
                except Exception as e:
                    with print_lock:
                        print(COLOR_ERROR + f"[!] Ошибка в строке {line_num}: {e}")
                    continue
        
        total_ips = loaded
        duration = time.time() - start_time
        with print_lock:
            print(COLOR_SUCCESS + f"\n[✓] Успешно загружено {loaded:,} IP ({loaded/duration:,.0f} IP/сек)")
            print(COLOR_HEADER + "-" * 60)
    
    except Exception as e:
        print(COLOR_ERROR + f"[!] Критическая ошибка: {e}")
        sys.exit(1)

def signal_handler(sig, frame):
    with print_lock:
        print(COLOR_ERROR + "\n[!] Остановка сканирования...")
    stop_event.set()
    sys.exit(0)

def main():
    print_banner()
    signal.signal(signal.SIGINT, signal_handler)
    
    if autoclear_found_on_start:
        try:
            with open(OUTPUT_FILE, 'w') as f:
                pass
            print(COLOR_SUCCESS + "[✓] Файл результатов очищен")
        except Exception as e:
            print(COLOR_ERROR + f"[!] Ошибка очистки файла: {e}")

    load_ranges()
    
    if total_ips == 0:
        print(COLOR_WARNING + "[!] Нет IP для сканирования!")
        return
    
    threading.Thread(target=title_updater, daemon=True).start()
    
    print(COLOR_HEADER + f"[•] Запуск {THREADS} потоков...")
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    while any(t.is_alive() for t in threads):
        time.sleep(0.5)
    
    stop_event.set()
    print(COLOR_SUCCESS + "\n[✓] Сканирование завершено!")
    print(COLOR_HEADER + "-" * 60)
    print(COLOR_TITLE + f"Всего проверено: {checked_ips}")
    print(COLOR_TITLE + f"Найдено открытых портов: {successful_ips}")

if __name__ == "__main__":
    from colorama import init
    init(autoreset=True)
    main()
