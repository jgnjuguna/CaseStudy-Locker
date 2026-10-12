FROM php:8.3-cli

RUN apt-get update && apt-get install -y --no-install-recommends 
    libsqlite3-dev 
    pkg-config 
    && docker-php-ext-install pdo_sqlite 
    && apt-get clean 
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

EXPOSE 10000

CMD ["php", "-S", "0.0.0.0:10000", "-t", "public", "public/router.php"]