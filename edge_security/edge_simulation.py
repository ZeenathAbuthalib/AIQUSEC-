import threading
import time

def edge_node(node_id):
    while True:
        data = f"Edge Node {node_id}: Monitoring value: {node_id * 10}"
        print(data)
        time.sleep(3)  # Simulating edge node activity

if __name__ == "__main__":
    # Creating multiple threads to represent different edge nodes
    threads = []
    for i in range(3):
        t = threading.Thread(target=edge_node, args=(i,))
        t.start()
        threads.append(t)

    # Keep the main program running
    for t in threads:
        t.join()
