from apscheduler.schedulers.background import BackgroundScheduler
import time

def periodic_task():
    print(f"Edge Node Task Executed at {time.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    scheduler.add_job(periodic_task, 'interval', seconds=10)
    scheduler.start()

    # Keep the script running to keep the scheduler active
    try:
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
