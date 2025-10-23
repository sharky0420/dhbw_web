FROM python:latest
EXPOSE 80

WORKDIR /usr/local/app

COPY templates ./templates
COPY app.py ./app.py
COPY wsgi.py ./wsgi.py

RUN pip install wheel
RUN pip install flask
RUN pip install gunicorn




CMD ["gunicorn", "--bind", "0.0.0.0:80", "wsgi:flask_app"]