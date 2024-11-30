import requests
import time

def send_data_to_server():
    while True:
        data = {"sensor_value": 42}  # Example data
        try:
            response = requests.post('http://127.0.0.1:5000/receive_data', json=data)
            print(f"Data sent: {response.status_code}")
        except Exception as e:
            print(f"Failed to send data: {e}")
        time.sleep(5)  # Send data every 5 seconds

if __name__ == "__main__":
    send_data_to_server()
