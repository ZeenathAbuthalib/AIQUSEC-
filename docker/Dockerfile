# Base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY ./ai_threat_detection/requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
COPY . .

# Install Flask
RUN pip install flask

# Expose the port Flask will run on
EXPOSE 5000

# Copy the start.sh script and make it executable
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Run the start.sh script
CMD ["./start.sh"]



