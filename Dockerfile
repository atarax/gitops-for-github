FROM python:3.9.15-slim

RUN mkdir /app
COPY requirements.txt /app
WORKDIR /app

RUN pip install -r requirements.txt

COPY app /app

CMD python gg.py
