FROM python:3

ADD config.json /app/
ADD requirements.txt /app/
ADD snort_blocklist_importer.py /app/

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "snort_blocklist_importer.py", "-d"]
