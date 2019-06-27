FROM python:3

ADD config.json ./config.json
ADD requirements.txt ./
ADD TalosBlacklistImporter.py ./

RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "./TalosBlacklistImporter.py", "-d" ]