import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORE_FILE = os.path.join(BASE_DIR, "global_store.json")

def _init_store():
    if not os.path.exists(STORE_FILE):
        with open(STORE_FILE, "w") as f:
            json.dump({
                "devices": {},
                "sessions": {}
            }, f, indent=4)

def load_store():
    _init_store()
    with open(STORE_FILE, "r") as f:
        return json.load(f)

def save_store(data):
    with open(STORE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def register_device(device_id, data):
    store = load_store()
    store["devices"][device_id] = data
    save_store(store)

def get_device(device_id):
    return load_store()["devices"].get(device_id)

def store_session(session_id, data):
    store = load_store()
    store["sessions"][session_id] = data
    save_store(store)