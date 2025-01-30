import os
import yaml
import re

# Fungsi untuk membaca daftar subdomain dari file
def read_subdomain_list(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    return []

# Fungsi untuk menyimpan subdomain yang digunakan ke file YAML
def save_subdomain_to_yaml(subdomain, yaml_file):
    with open(yaml_file, 'w') as file:
        yaml.dump({'subdomain': subdomain}, file)

# Fungsi untuk membaca subdomain terakhir dari file YAML
def read_subdomain_from_yaml(yaml_file):
    if os.path.exists(yaml_file):
        with open(yaml_file, 'r') as file:
            data = yaml.load(file, Loader=yaml.FullLoader)
            return data.get('subdomain', None)
    return None

# Fungsi untuk mengganti subdomain di _worker.js
def replace_subdomain_in_workerjs(workerjs_file, new_subdomain, old_subdomain):
    with open(workerjs_file, 'r') as file:
        lines = file.readlines()

    updated_lines = []
    for line in lines:
        # Hanya mengganti subdomain yang sesuai (contoh: xxx.bmkg.xyz) dengan subdomain baru
        if old_subdomain in line:
            line = re.sub(r'\b' + re.escape(old_subdomain) + r'\.bmkg\.xyz', new_subdomain + '.bmkg.xyz', line)
        updated_lines.append(line)

    with open(workerjs_file, 'w') as file:
        file.writelines(updated_lines)

def main():
    yaml_file = 'subdomain.yml'
    workerjs_file = '_worker.js'
    list_file = 'subdomain_list.txt'

    # Baca daftar subdomain dari file
    subdomain_list = read_subdomain_list(list_file)
    if not subdomain_list:
        print("Subdomain list is empty or not found!")
        return

    # Baca subdomain terakhir dari YAML
    last_subdomain = read_subdomain_from_yaml(yaml_file)

    if last_subdomain is None:
        print("No subdomain found in subdomain.yml!")
        return

    # Pastikan subdomain terakhir ada dalam daftar
    if last_subdomain not in subdomain_list:
        print(f"Last subdomain '{last_subdomain}' not in subdomain list!")
        return

    # Cari subdomain berikutnya berdasarkan urutan di daftar
    current_index = subdomain_list.index(last_subdomain)
    next_index = (current_index + 1) % len(subdomain_list)
    next_subdomain = subdomain_list[next_index]

    # Ganti subdomain di _worker.js
    replace_subdomain_in_workerjs(workerjs_file, next_subdomain, last_subdomain)

    # Simpan subdomain yang digunakan ke file YAML
    save_subdomain_to_yaml(next_subdomain, yaml_file)
    print(f"Subdomain updated to: {next_subdomain}")

if __name__ == "__main__":
    main()
