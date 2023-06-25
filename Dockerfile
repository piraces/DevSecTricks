FROM python:latest
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY get_sitemap_links.py /app/get_sitemap_links.py

CMD ["python3", "/app/get_sitemap_links.py", "https://book.devsec.fyi/sitemap.xml"]