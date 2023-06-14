FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  git \
  curl \
  python3-pip \
  gpg
RUN curl -fsSL https://repo.wabarc.eu.org/apt/gpg.key | gpg --dearmor -o /usr/share/keyrings/packages.wabarc.gpg
RUN echo "deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/packages.wabarc.gpg] https://repo.wabarc.eu.org/apt/ /" | tee /etc/apt/sources.list.d/wayback.list
RUN apt update && apt install wayback -y && rm -rf /var/lib/apt/lists/*

COPY get_and_backup_links.py /
RUN mkdir /app
WORKDIR /app

ENTRYPOINT ["python3", "-u", "/get_and_backup_links.py", "/app"] # Path:to the main folder to scan