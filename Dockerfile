FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Запускаем и бота и API в одном контейнере
CMD python -m uvicorn main:app --host 0.0.0.0 --port $PORT & python bot.py
