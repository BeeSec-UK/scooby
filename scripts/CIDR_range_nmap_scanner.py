import subprocess
import os

# todo: please change these globals if needed!!
process_number = 40
output_directory_name = 'output'
target_ip_ranges_filepath = 'targets.txt'

if not os.path.exists(output_directory_name):
    os.makedirs(output_directory_name)


def read_ip_ranges(filepath):
    """
    Returns the ip range names and their corresponding CIDR ranges from the targets file.
    :param filepath: The path to the file to read.
    :return: ip range names and their corresponding CIDR ranges from the targets file.
    """
    ips_and_names = {}
    with open(filepath, 'r') as f:
        for line in f:
            ip_range, ip_name = line.strip().split(' : ')
            ips_and_names[ip_range] = ip_name
    return ips_and_names


# ips_and_names = read_ip_ranges(target_ip_ranges_filepath)


# nmap -sL | grep '^Nmap scan' | cut -d " " -f 5 | tee
def generate_ip_list_for_CIDR(ip_range, ip_range_name):
    """
    Performs a list scan on the specified ip CIDR range, putting the output in a specified directory.
    :param ip_range: The CIDR range to scan.
    :param ip_range_name: The name of the CIDR range to scan.
    """
    print(f"## Generating ip list for the range {ip_range} called {ip_range_name}")

    if not os.path.exists(f"{output_directory_name}/{ip_range_name}"):
        os.makedirs(f"{output_directory_name}/{ip_range_name}", exist_ok=True)

    if not os.path.exists(f"{output_directory_name}/{ip_range_name}/nmap-{ip_range_name}-target-ips.txt"):
        with open(f"{output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt", 'w') as file:
            file.write('')

    command = f"nmap -sL {ip_range} | grep '^Nmap scan' | cut -d ' ' -f 5 | tee {output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt"
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")


# cat targets.txt | xargs -I % -P 10 sudo nmap % -sSV -vv -p- -Pn -n -A -T4 -oA nmap-BeeSecLab-TCP_ALL-%
def full_nmap_tcp_scan(ip_range, ip_range_name):
    if not os.path.exists(f"{output_directory_name}/{ip_range_name}/TCP-FULLSCAN"):
        os.makedirs(f"{output_directory_name}/{ip_range_name}/TCP-FULLSCAN", exist_ok=True)

    print(f"## Performing full TCP scan against the ip range {ip_range} called {ip_range_name} ##")
    print("## WARNING: This scan requires root permissions and it wont show if you are using an IDE. Enter your password:\n")
    command = (f"cat {output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt | "
               f"xargs -I % -P {process_number} "
               f"sudo nmap % -sSV -vv -p- -Pn -n -A -T4 -oA {output_directory_name}/{ip_range_name}/TCP-FULLSCAN/nmap-{ip_range_name}-TCP-FULLSCAN-%")
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")


# Discovery Scan
#   cat targets.txt | xargs -I % -P 10 sudo nmap % -sS -vv –top-ports=2000 -Pn -n -oA nmap-BeeSecLab-Top2k-%
def discovery_scan(ip_range, ip_range_name):
    if not os.path.exists(f"{output_directory_name}/{ip_range_name}/TCP-Top2k"):
        os.makedirs(f"{output_directory_name}/{ip_range_name}/TCP-Top2k", exist_ok=True)
    print(f"## Performing discovery scan against the ip range {ip_range} called {ip_range_name} ##")
    print("## WARNING: This scan requires root permissions and it wont show if you are using an IDE. Enter your password:\n")
    command = (f"cat {output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt | "
               f"xargs -I % -P {process_number} "
               f"sudo nmap % -sS -vv -top-ports=2000 -Pn -n -oA {output_directory_name}/{ip_range_name}/TCP-Top2k/nmap-{ip_range_name}-TCP-Top2k-%")
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")


# UDP Scan
#   cat targets.txt | xargs -I % -P 10 sudo "nmap % -sU -vv --top-ports=2000 -Pn -n -T4 -oA nmap-BeeSecLab-UDP_Top2k-%
def udp_scan(ip_range, ip_range_name):
    if not os.path.exists(f"{output_directory_name}/{ip_range_name}/UDP-Top2k"):
        os.makedirs(f"{output_directory_name}/{ip_range_name}/UDP-Top2k", exist_ok=True)
    print(f"## Performing UDP scan against the ip range {ip_range} called {ip_range_name} ##")
    print("## WARNING: This scan requires root permissions and it wont show if you are using an IDE. Enter your password:\n")
    command = (f"cat {output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt | "
               f"xargs -I % -P {process_number} "
               f"sudo nmap % -sU -vv --top-ports=2000 -Pn -n -T4 -oA {output_directory_name}/{ip_range_name}/UDP"
               f"-Top2k/nmap-{ip_range_name}-UDP-Top2k-%")
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")


def basic_scan(ip_range, ip_range_name):
    if not os.path.exists(f"{output_directory_name}/{ip_range_name}/Basic-scan"):
        os.makedirs(f"{output_directory_name}/{ip_range_name}/Basic-scan", exist_ok=True)
    print(f"## Performing basic nmap scan against the ip range {ip_range} called {ip_range_name} ##")
    command = (f"cat {output_directory_name}/{ip_range_name}/{ip_range_name}-target-ips.txt | "
               f"xargs -I % -P {process_number} "
               f"nmap % -Pn -oA {output_directory_name}/{ip_range_name}/Basic-scan/nmap-{ip_range_name}-Basic-scan-%")
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")

# for ip_range, ip_name in ips_and_names.items():
#    generate_ip_list(ip_range, ip_name)

# with open(target_ip_ranges_filepath, 'r') as f:
#     for line in f:
#         ip_range, ip_name = line.strip().split(' : ')
#         generate_ip_list(ip_range, ip_name)
#         #basic_scan(ip_range, ip_name)
#         #discovery_scan(ip_range, ip_name)
#         full_nmap_tcp_scan(ip_range, ip_name)
#         #udp_scan(ip_range, ip_name)

# for ip_range, ip_name in ips_and_names.items():
#     discovery_scan(ip_range, ip_name)
#     full_nmap_tcp_scan(ip_range, ip_name)
#     udp_scan(ip_range, ip_name)
