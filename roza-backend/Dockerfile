FROM php:8.2-cli

RUN docker-php-ext-install mysqli

WORKDIR /app
COPY . /app

EXPOSE 10000

CMD ["php", "-S", "0.0.0.0:10000", "roza-backend/roza_api.php"]