import time
conversations = {}

def update_conversation(conv_id):
    if conv_id not in conversations:
        conversations[conv_id] = {"start_time": time.time(), "turns": 0}
    conversations[conv_id]["turns"] += 1

def get_metrics(conv_id):
    data = conversations.get(conv_id, {"start_time": time.time(), "turns": 1})
    return data["turns"], int(time.time() - data["start_time"])