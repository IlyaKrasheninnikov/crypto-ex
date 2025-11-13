FROM python:3.13-slim

WORKDIR /app

RUN mkdir -p uploads/kyc

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5003

CMD ["python", "app.py"]