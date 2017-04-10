import json

import securesystemslib.util

with open('timestamp.json', 'r+') as file_object:
  timestamp_content = securesystemslib.util.load_json_file('timestamp.json')
  large_data = 'LargeTimestamp' * 10000
  timestamp_content['signed']['_type'] = large_data
  json.dump(timestamp_content, file_object, indent=1, sort_keys=True)

