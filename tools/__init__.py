import json


def read_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        config = json.load(file)
    return config