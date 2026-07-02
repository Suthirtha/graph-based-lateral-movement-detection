import bz2
import json

file_path = "data/wls_day-01.bz2"

with bz2.open(file_path, "rt") as file:
    for i, line in enumerate(file):
        record = json.loads(line)
        print(record)
        print("\nColumns:")
        print(record.keys())
        break