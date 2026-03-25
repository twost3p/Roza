# Use official PHP CLI image
FROM php:8.2-cli

# Set working directory
WORKDIR /app

# Copy all files from your repo into the container
COPY . /app

# Expose the port your PHP server will run on
EXPOSE 10000

# Start the PHP built-in server
CMD ["php", "-S", "0.0.0.0:10000", "roza_API.php"]