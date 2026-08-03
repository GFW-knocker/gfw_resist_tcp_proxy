import subprocess
import os
import time
import sys
import signal


scripts = ['vio_client.py', 'quic_client.py']


def run_script(script_name):
    if os.name == 'nt':
        # Windows
        p = subprocess.Popen(['python', script_name])
    else:
        # linux
        os.system(f"pkill -f {script_name}")
        time.sleep(0.5)
        p = subprocess.Popen(['python3', script_name])
    return p


processes = []
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    for p in processes:
        print("terminated:",p)
        p.terminate()

    sys.exit(0)


if __name__ == "__main__":
    p1 = run_script(scripts[0])
    time.sleep(1)
    p2 = run_script(scripts[1])
    processes = [p1,p2]
    signal.signal(signal.SIGINT, signal_handler)
    p1.wait()
    p2.wait()
    print("All subprocesses have completed.")

