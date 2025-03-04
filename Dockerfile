FROM python:3.11

RUN pip install fastapi sqlalchemy psycopg2 kubernetes uvicorn shortuuid

ENV hi=1011
COPY ./manage_api.py /
COPY ./sql-files/migrate.sql /

CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8080", "manage_api:app"]
