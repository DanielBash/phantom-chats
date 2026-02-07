# Phantom-Chats
> Анонимность, простота и полный контроль над своими данными.

Phantom chats - анонимный мессенджер разрабатываемый небольшой командой разработчиков.
Главная его цель - дать вам *уверенность*, что ваши данные в ежовых рукавицах.

## Локальная установка
### СПОСОБ 1: Виртуальное окружение (Linux)
1) Склонируйте репозиторий
```bash
git clone https://github.com/DanielBash/phantom-chats.git
cd phantom-chats
```

2) Установите зависимости в виртуальном окружении
```bash
python -m venv .venv
source venv/bin/activate
pip install -r requirements.txt
nano .env # добавьте секретные переменные для использования всех функций
```

3) Запустите сервер
```bash
python mian.py
```
