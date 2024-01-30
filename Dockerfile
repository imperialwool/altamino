FROM python:3.12.0-slim-bookworm

USER root

EXPOSE 80

ENV docker 1

RUN apt-get update && apt-get install lsb-release curl gpg gcc cmake build-essential libgl1 libglib2.0-0 -y
RUN curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list
RUN apt-get update && apt-get install redis -y

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY . /app
RUN chmod -R 777 /app
WORKDIR /app

CMD "./start.sh"