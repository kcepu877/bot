import sys
import subprocess
import re
import time
import os

# Automatically install required dependencies
try:
    import requests
except ImportError:
    print("Attempting to automatically install required dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        print("Dependency installed successfully. Please re-run the script!")
        sys.exit(0)
    except Exception as e:
        print("Automatic installation failed. Please manually execute the following command:")
        print(f"    {sys.executable} -m pip install requests")
        sys.exit(1)

# Define output files
output_file = "proxies.txt"
temp_file = "temp_proxies.txt"

# Clear the output files
open(output_file, 'w').close()
open(temp_file, 'w').close()

print("Fetching country codes...")
response = requests.get("https://cfip.ashrvpn.v6.army")
countries = re.findall(r'value="([A-Z]{2})"', response.text)

# Fetch proxy data for each country
with open(temp_file, 'a') as temp_f:
    for country in countries:
        print(f"Fetching data for country {country}...")
        try:
            response = requests.get(f"https://cfip.ashrvpn.v6.army/?country={country}")
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            for proxy in proxies:
                ip, port = proxy.split(':', 1)
                temp_f.write(f"{ip} {port}\n")
            time.sleep(1)  # Delay to avoid overwhelming the server
        except Exception as e:
            print(f"Error fetching {country}: {str(e)}")

# Remove duplicates and sort the proxies
with open(temp_file, 'r') as f:
    lines = f.read().splitlines()

unique_proxies = sorted(set(lines), key=lambda x: (x.split('.')[0], x.split('.')[1], x.split('.')[2], x.split('.')[3]))

with open(output_file, 'w') as f:
    f.write('\n'.join(unique_proxies))

# Clean up temporary file
os.remove(temp_file)

print(f"Completed! Results saved to {output_file} (duplicates removed)")
print("Now running ./iptest -file", output_file)
subprocess.run(["./iptest", "-file", output_file, "-max", "50"])
print("Done!")
