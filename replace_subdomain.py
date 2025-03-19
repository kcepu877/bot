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

# Fungsi untuk mengganti subdomain di js/_worker.js
def replace_subdomain_in_worker_js(worker_js_file, new_subdomain, old_subdomain):
    with open(worker_js_file, 'r') as file:
        content = file.read()

    # Hanya mengganti subdomain yang sesuai (contoh: xxx.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg) dengan subdomain baru
    updated_content = re.sub(r'\b' + re.escape(old_subdomain) + r'\.bmkg\.xyz', new_subdomain + '.bmkg.xyz', content)

    with open(worker_js_file, 'w') as file:
        file.write(updated_content)

# Fungsi untuk mengganti subdomain di index.html
def replace_subdomain_in_html(html_file, new_subdomain, old_subdomain):
    with open(html_file, 'r') as file:
        content = file.read()

    # Hanya mengganti subdomain yang sesuai (contoh: xxx.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg) dengan subdomain baru
    updated_content = re.sub(r'\b' + re.escape(old_subdomain) + r'\.bmkg\.xyz', new_subdomain + '.bmkg.xyz', content)

    with open(html_file, 'w') as file:
        file.write(updated_content)

def main():
    yaml_file = 'subdomain.yml'
    worker_js_file = 'js/_worker.js'  # Mengganti _worker.js menjadi js/_worker.js
    html_file = 'index.html'          # Menambahkan index.html
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

    # Ganti subdomain di js/_worker.js dan index.html
    replace_subdomain_in_worker_js(worker_js_file, next_subdomain, last_subdomain)
    replace_subdomain_in_html(html_file, next_subdomain, last_subdomain)

    # Simpan subdomain yang digunakan ke file YAML
    save_subdomain_to_yaml(next_subdomain, yaml_file)
    print(f"Subdomain updated to: {next_subdomain}")

if __name__ == "__main__":
    main()
