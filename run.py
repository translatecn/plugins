# encoding='utf8'
import os

main_path = set()

for cd, dirs, files in os.walk('.'):
    for file in files:
        if not file.endswith('.go'):
            continue
        with open(os.path.join(cd, file), 'r', encoding='utf8') as f:
            data = f.read()
            if 'package main' in data and 'package main_test' not in data:
                main_path.add(cd)
print(main_path)

for path in main_path:
    print(path)
    os.system(f'cd {path}; go build . ; go clean .')