************
<div align="center">
  <h1>MV Fast Port Scanner</h1>
</div>

## ❤️ Цель: 15 звёздочек = обновление

<div align="center">
    <img src="https://github.com/user-attachments/assets/eb6c1441-a428-4e92-8918-63fdc654dc10" alt="banner" />
</div>


## 🌟 Особенности

- 🚀 **Высокая производительность** за счет многопоточности и асинхронных запросов
- 🎨 **Интуитивный интерфейс** с цветовым оформлением
- 📁 **Автоматическая обработка** IP-диапазонов из файла
- ⚙️ **Автоустановка зависимостей** при первом запуске
- 📊 **Интерактивный прогресс-бар** с статистикой
- 💾 **Сохранение результатов** в файл

## 📋 Требования

- Python 3.7+
- Поддержка IPv4
- свободное место

## 🛠️ Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/MrVINIK/MVFPS.git
cd MVFPS
```
или (на Windows)
скачайте актуальную версию в https://github.com/MrVINIK/MVFPS/releases
распакуйте, поместите ваши диапазоны, настройте программу
2. Убедитесь, что Python установлен:
```
python --version
```

Запустите программу (зависимости установятся автоматически):
all systems:
```
python app.py
```
или, если вы на Windows, то можете и запустить через run.bat



## 🖥️ Использование

### Загрузка в файл диапазонов
Создайте/откройте файл `ranges.txt` и загрузите диапазоны в формате:
```text
192.168.1.1-192.168.1.255
10.0.0.1-10.0.0.100
```
вы можете загрузить диапазоны также с этого сайта: https://suip.biz/ru/?act=all-country-ip

## ⚙️ Конфигурация
```python
# Настройки
PORT = 8000                       # Сканируемый порт
THREADS = 10000                   # Количество потоков
RANGES_FILE = "ranges.txt"        # файл загрузки диапазонов
OUTPUT_FILE = "found_ips.txt"     # файл вывода (там, де порты открыты)
TIMEOUT = 2.5                     # Таймаут подключения (сек). Чем меньше время ожидания ответа от IP при сканировании, тем быстрее поток освободится
UPDATE_INTERVAL = 0.1             # Время обновления прогрессов, лучше не трогать
BATCH_SIZE = 1000000              # Размер пачки IP, для обработки.
autoclear_found_on_start = True   # автоочистка файла вывода при запуске. False - отключить
```

### 3. Пример работы
```
[•] Загрузка диапазонов IP...
[✓] Успешно загружено 1,048,576 IP (500,000 IP/сек)
------------------------------------------------------------
[•] Прогресс: [■■■■■■■■■■■■■■■■■■■■■■■          ] Всего: 800000/1048576 | Открыто: 12 | Успех: 0.0015%
```

## 🚨 Обработка ошибок
Программа автоматически:
- Пропускает некорректные строки в файле
- Игнорирует IPv6 диапазоны
- Сохраняет прогресс при аварийном завершении
- Логирует ошибки в консоль

## 📄 Лицензия
MIT License - [Подробнее](https://github.com/MrVINIK/MVFPS/blob/main/LICENSE)

## 📧 Поддержка
Обнаружили проблему? Создайте [Issue](https://github.com/MrVINIK/MVFPS/issues)

---

**⚠️ Внимание!** Используйте в образовательных целях. Автор не несет ответственности за неправомерное использование.
