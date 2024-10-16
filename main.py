import os
import re
import xml.dom.minidom
from scripts.CIDR_range_nmap_scanner import read_ip_ranges, output_directory_name, temp_directory, targets, \
    generate_ip_list_for_CIDR, basic_scan, discovery_scan, udp_scan, full_nmap_tcp_scan
from scripts.http_get_improved import get_terminal_output
from scripts.run_commands import run_command, run_verbose_command, run_verbose_command_with_input


def remove_ansi_escape_sequences(text: str) -> str:
    """
    Removes ANSI escape sequences from a string.
    :param text: The text to remove ANSI escape sequences from.
    :return: The string with ANSI escape sequences removed.
    """
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)


def cleanup(ips_and_names: str, temp_directory: str) -> None:
    """
    Cleans up the working directory of certain output files.
    :param ips_and_names: The CIDR ranges and their names.
    :param temp_directory: The name of the temp directory.
    """
    # todo here i want the cleanup stuff in line 4
    if os.path.exists(temp_directory):
        run_command(f"rm -rf {temp_directory}")
    for file in os.listdir('.'):
        if file.startswith("nMap_Merged"):
            os.remove(file)
    for r in ips_and_names.values():
        if os.path.exists(f"{output_directory_name}/{r}"):
            run_command(f"rm -rf {output_directory_name}/{r}")


def merge_nmap_xml_files(xml_files_location: str, cidr_range_name: str) -> str:
    """
    Merges the xml files from the outputs of the nmap scans.
    :param xml_files_location: The filepath of the xml files to be merged.
    :param cidr_range_name: The name of the current cidr range.
    :return: The full filepath of the merged xml file.
    """
    merger_output_filename = f"{cidr_range_name}-merged.xml"
    merger_output_full_filepath = f'{output_directory_name}/{cidr_range_name}/{merger_output_filename}'
    command = f"python scripts/merger-improved.py -d {xml_files_location} -o {merger_output_full_filepath}"
    run_verbose_command(command)

    # format the file
    with open(merger_output_full_filepath, 'r') as file:
        xml_content = file.read()

    temp = xml.dom.minidom.parseString(xml_content)
    formatted_xml = temp.toprettyxml(indent="  ")

    with open(merger_output_full_filepath, 'w') as file:
        file.write(formatted_xml)

    # locate and return this merged file
    for file in os.listdir(f'{output_directory_name}/{cidr_range_name}/'):
        if file == merger_output_filename:
            return f'{output_directory_name}/{cidr_range_name}/{file}'


def determine_scan_type(basic_scan_dir: str, top2k_scan_dir: str) -> str:
    """
    Determines the type of scan being performed
    :return: A string with the type of scan being performed.
    """
    s = None
    # determine which scan type to use
    if os.path.isdir(basic_scan_dir) and not os.path.isdir(top2k_scan_dir):
        s = "Basic-scan"
        print(f"####### using {s}")
    elif os.path.isdir(top2k_scan_dir):
        s = "TCP-Top2k"
        print(f"####### using {s}")
    return s


def run_autosslscan(autosslscan_output_directory: str, merged_xml_filepath: str) -> None:
    """
    Runs autosslscan using the merged xml file.
    :param autosslscan_output_directory: The directory where the output from autosslscan is going to go.
    :param merged_xml_filepath: The filepath of the merged xml file.
    """
    os.makedirs(autosslscan_output_directory, exist_ok=True)
    command = f"python scripts/autosslscan.py -i {merged_xml_filepath} -o {autosslscan_output_directory} -t 10"
    print(command)
    run_verbose_command(command)


def run_httpget(httpget_output_directory: str, merged_xml_filepath: str) -> str:
    """
    Runs httpget using the merged xml file.
    :param httpget_output_directory: The output directory where the output from httpget is going to go.
    :param merged_xml_filepath: The filepath of the merged xml file.
    :return: Returns the string output of the httpget command.
    """
    os.makedirs(httpget_output_directory, exist_ok=True)
    command = f'python scripts/http_get_improved.py -x {merged_xml_filepath}'
    output = run_verbose_command_with_input(command, httpget_output_directory)
    return output

def main():
    # make the temp and the output directory
    if not os.path.exists(output_directory_name):
        os.makedirs(output_directory_name)
    if not os.path.exists(temp_directory):
        os.makedirs(temp_directory)

    # get the cidr range and it's name from the target file
    ips_and_names = read_ip_ranges(targets)
    # clean up the working dir
    cleanup(ips_and_names, temp_directory)

    # for each cidr in the targets file, generate an ip list for it
    for cidr_range, cidr_range_name in ips_and_names.items():
        # print(cidr_range, cidr_range_name)
        generate_ip_list_for_CIDR(cidr_range, cidr_range_name)

    for cidr_range, cidr_range_name in ips_and_names.items():
        current_cidr_range_output_directory = f"{output_directory_name}/{cidr_range_name}"

        basic_scan(cidr_range, cidr_range_name)
        # discovery_scan(cidr_range, cidr_range_name)
        # udp_scan(cidr_range, cidr_range_name)
        # full_nmap_tcp_scan(cidr_range, cidr_range_name)

        basic_scan_dir = f"{current_cidr_range_output_directory}/Basic-scan"
        top2k_scan_dir = f"{current_cidr_range_output_directory}/TCP-Top2k"

        if not (os.path.isdir(basic_scan_dir) or os.path.isdir(top2k_scan_dir)):
            raise Exception("YOU HAVE TO DO EITHER A BASIC SCAN OR A TCP-TOP2k (DISCOVERY) SCAN")

        # determine the scan type for this cidr
        scan_type = determine_scan_type(basic_scan_dir, top2k_scan_dir)

        # merge the xml files from the nmap scans
        xml_files_location = f'{current_cidr_range_output_directory}/{scan_type}/'
        merged_xml_filepath = merge_nmap_xml_files(xml_files_location, cidr_range_name)
        # print(merged_xml_filepath)

        # perform autosslscan
        autosslscan_output_directory = f"{current_cidr_range_output_directory}/autosslscan-output"
        run_autosslscan(autosslscan_output_directory, merged_xml_filepath)

        # perform http-get
        httpget_output = f'{current_cidr_range_output_directory}/http-get-output'
        out = run_httpget(httpget_output, merged_xml_filepath)
        with open(f'{httpget_output}/http-get-terminal-output.txt', 'w') as file:
            file.write(remove_ansi_escape_sequences(out))
        for txt in os.listdir(httpget_output):
            with open(f'{httpget_output}/{txt}', 'r') as file:
                temp = file.read()
            with open(f'{httpget_output}/{txt}', 'w') as file:
                file.write(remove_ansi_escape_sequences(temp))

if __name__ == '__main__':
    main()
    