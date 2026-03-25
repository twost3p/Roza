# Use PHP CLI image
FROM php:8.2-cli

# Install dependencies for PostgreSQL PDO
RUN apt-get update && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Set working directory
WORKDIR /app

# Copy your project files
COPY . /app

# Expose port
EXPOSE 10000

# Start the PHP built-in server
CMD ["php", "-S", "0.0.0.0:10000", "roza-backend/roza_api.php"]