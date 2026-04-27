# RedCheck Protocol Generator

Автоматический генератор протокола информационной безопасности по результатам сканирования RedCheck.

## Возможности

- **Поддержка N хостов**: Обработка отчетов для любого количества хостов
- **Три типа отчетов**:
  - Инвентаризация (inventory) — сведения об ОС, железе, ПО, пользователях, службах
  - Пентест/скан портов — открытые порты, сервисы, SMB-настройки
  - Уязвимости — CVE, CVSS, статус эксплуатации
- **Гибкий парсинг XML**: Поддержка различных форматов XML-отчетов
- **Парсинг текстовых логов**: Regex + state machine для text-based отчетов
- **GUI на PySide6**: Удобный интерфейс для выбора файлов и генерации
- **CLI режим**: Автоматизация через командную строку
- **Модульная архитектура**: Легко расширяется под новые форматы отчетов

## Установка

```bash
pip install PySide6 python-docx lxml
```

## Использование

### Графический интерфейс

```bash
python main.py --gui
```

1. Выберите количество хостов
2. Для каждого хоста загрузите 3 файла:
   - Отчет инвентаризации (XML)
   - Отчет пентеста (XML/TXT)
   - Отчет уязвимостей (XML)
3. Выберите шаблон DOCX
4. Нажмите "Сгенерировать протокол"

### Командная строка

```bash
# Один хост
python main.py -i inventory.xml -p pentest.xml -v vulns.xml -t template.docx -o protocol.docx

# Создать образец шаблона
python main.py --create-template -t template.docx

# Подробный вывод
python main.py -i inv.xml -p p.xml -v v.xml -V
```

## Структура проекта

```
redcheck_protocol_app/
├── main.py              # Точка входа (CLI + GUI)
├── doc_generator.py     # Генерация DOCX из шаблона
├── core/
│   ├── models.py        # Модели данных (Host, PortScan, Vulnerability)
│   └── parser_interface.py  # Интерфейс парсеров
├── parsers/
│   ├── inventory_parser.py    # Парсер инвентаризации
│   ├── pentest_parser.py      # Парсер пентеста
│   └── vulnerability_parser.py # Парсер уязвимостей
├── gui/
│   └── app.py           # PySide6 GUI приложение
├── sample_data/         # Примеры отчетов
├── templates/           # Шаблоны документов
└── logs/               # Логи приложения
```

## Форматы отчетов

### Инвентаризация (XML)
Ожидается структура с элементами: host, os, hardware, network, software, users, services

### Пентест (XML/TXT)
- XML: элементы host, ports, port, service, smb
- TXT: формат nmap-like с портами и баннерами

### Уязвимости (XML)
Элементы: vulnerability, cve, severity, cvss_score, exploit, solution

## Расширение

Для добавления поддержки нового формата отчета:
1. Создайте новый класс-парсер в `parsers/`, наследуясь от `ParserInterface`
2. Добавьте распознавание формата в соответствующий парсер
3. При необходимости расширьте модели в `core/models.py`

## Логирование

Логи сохраняются в `logs/app.log`. Уровень логирования регулируется флагом `-V`.

## Требования

- Python 3.11+
- PySide6
- python-docx
- lxml

## Лицензия

MIT
