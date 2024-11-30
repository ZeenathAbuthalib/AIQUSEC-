# edge_node.py
import time
import random

def edge_task():
    # Simulate an edge task that performs monitoring or some data processing
    while True:
        data = random.randint(0, 100)  # Example of monitoring data
        print(f"Edge Node: Monitoring data: {data}")
        time.sleep(5)  # Perform this task every 5 seconds

if __name__ == "__main__":
    edge_task()
