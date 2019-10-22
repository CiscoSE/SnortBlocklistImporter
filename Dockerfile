FROM python:3

ADD config.json /app/
ADD requirements.txt /app/
ADD talos_blacklist_importer.py /app/

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "talos_blacklist_importer.py", "-d"]
