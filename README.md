![Placeholder](https://github.com/DanielBash/phantom-chats/blob/main/static/images/repoimage.png?raw=true)
[![Flask tests](https://github.com/DanielBash/phantom-chats/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/DanielBash/phantom-chats/actions/workflows/python-tests.yaml)
![Team Members](https://img.shields.io/badge/team_members-2-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Stars](https://img.shields.io/github/stars/DanielBash/phantom-chats)

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
