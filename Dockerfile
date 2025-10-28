FROM python:latest
EXPOSE 80

ENV BANK_DB_PATH=/var/data/database.db

WORKDIR /usr/local/app

COPY templates ./templates
COPY app.py ./app.py
COPY wsgi.py ./wsgi.py
COPY database_util.py ./database_util.py
COPY utility.py ./utility.py

RUN pip install wheel
RUN pip install flask
RUN pip install gunicorn


RUN mkdir /var/data

CMD ["gunicorn", "--bind", "0.0.0.0:80", "wsgi:flask_app"]