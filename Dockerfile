FROM python:3.12.0-slim-bookworm

USER root

ENV docker 1

RUN apt update && apt install gcc cmake build-essential -y

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY . /app
RUN chmod -R 777 /app
WORKDIR /app

CMD "./start.sh"

EXPOSE 80