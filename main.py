from scripts.CIDR_range_nmap_scanner import (generate_ip_list_for_CIDR, read_ip_ranges, target_ip_ranges_filepath,
                                             basic_scan, output_directory_name, discovery_scan, full_nmap_tcp_scan)

from scripts.run_commands import run_command, run_verbose_command, run_verbose_command_with_input

import os
import xml.dom.minidom
import multiprocessing

def scan_task(ip_range, ip_range_name):
    # This function will handle individual IP range scanning
    generate_ip_list_for_CIDR(ip_range, ip_range_name)
    basic_scan(ip_range, ip_range_name)
    # Uncomment to add more scan types:
    # discovery_scan(ip_range, ip_range_name)
    # full_nmap_tcp_scan(ip_range, ip_range_name)
    # udp_scan(ip_range, ip_range_name)

def parallel_scan(ips_and_names):
    pool = multiprocessing.Pool(processes=65)
    scan_tasks = [(ip_range, ip_range_name) for ip_range, ip_range_name in ips_and_names.items()]
    pool.starmap(scan_task, scan_tasks)
    pool.close()
    pool.join()

def main():
    ips_and_names = read_ip_ranges(target_ip_ranges_filepath)
    temp_directory = "temp"
    cleanup(ips_and_names, temp_directory)
    parallel_scan(ips_and_names)

    # so we are going to look into the output directories for the outputted .xml files.
    for ip_range, ip_range_name in ips_and_names.items():

        # Discovery scan = TCP-Top2k
        # UDP Scan = UDP-Top2k
        # Full TCP = TCP-FULLSCAN

        # todo so ive decided that you have to either do a basic scan or a tcp top2k.
        # todo this next section is about correctly getting the nmapmerger file so that there arent any dupes, which is why you have
        #  to do either a basic or top2k
        if not any(os.path.isdir(f"{output_directory_name}/{ip_range_name}/{scan}") for scan in ["Basic-scan", "TCP-Top2k"]):
            raise Exception("YOU HAVE TO DO EITHER A BASIC SCAN OR A TCP-TOP2k (DISCOVERY) SCAN")

        basic = os.path.isdir(f"{output_directory_name}/{ip_range_name}/Basic-scan")
        top2k = os.path.isdir(f"{output_directory_name}/{ip_range_name}/TCP-Top2k")
        output_nmap_xmls = []

        # so basically, if we did a top2k and not a basic or a basic and a top2k, then it takes the top2k output files.
        # or if we did a basic and not a top2k, then obviously we take the basic scan output files and merge them!
        # thats what this whole part is about. Its about getting the correct set of files for the nmap merger, because we only want ONE
        # certain set (top2k or basic). And when i say "set" i mean all of the the output .xml files from the nmap scans against a CIDR range.
        # Instead of taking MORE THAN ONE SET which is what i was doing before, which would mess up the nmapmerger, we now only take either
        # basic scan or top2k to use as our set of output files. We prioritise top2k though.
        if basic and not top2k:
            scan_type = "Basic-scan"
            print(f"####### using {scan_type}")
        elif top2k:
            scan_type = "TCP-Top2k"
            print(f"####### using {scan_type}")

        directory = f"{output_directory_name}/{ip_range_name}/{scan_type}"
        if os.path.isdir(directory):
            output_nmap_xmls.extend([f"{directory}/" + f for f in os.listdir(directory) if f.endswith('.xml')])

        if output_nmap_xmls is not None:
            # create the temp directory
            if not os.path.exists(f"{temp_directory}"):
                os.makedirs(f"{temp_directory}", exist_ok=True)

            # for each output file, copy it to a temp directory
            # then run nmap merger on that directory
            for xml_file in output_nmap_xmls:
                stripped_string = "nmap" + xml_file.split("nmap", 1)[1]
                command = f"cp {xml_file} {temp_directory}/{stripped_string}"
                run_command(command)

            # now we merge all the nmap xmls in the temp directory into one!
            merger_output_filename = f"{ip_range_name}-merged.xml"
            merger_output_path = f"{output_directory_name}/{ip_range_name}/{scan_type}/{merger_output_filename}"
            command = f"python scripts/merger-improved.py -d {temp_directory} -o {merger_output_path}"
            run_verbose_command(command)

            # so nmap merge outputs files that always begin with 'nMap_merged' and are .xml files,
            # so we are going to look for these files.
            # This won't work properly if there are more than one nmap merge output files in the directory!!


            if merger_output_path is not None:

                # format xml file
                with open(merger_output_path, 'r') as file:
                    xml_content = file.read()

                temp = xml.dom.minidom.parseString(xml_content)
                formatted_xml = temp.toprettyxml(indent="  ")

                with open(merger_output_path, 'w') as file:
                    file.write(formatted_xml)

                command = f"cp {merger_output_path} {output_directory_name}/{ip_range_name}"
                run_command(command)
                print(f"successfully copied {merger_output_path} to {output_directory_name}/{ip_range_name}")

                # now we perform autosslscan and http-get.
                autosslscan_output_directory = f"{output_directory_name}/{ip_range_name}/autosslscan-output"

                if not os.path.exists(autosslscan_output_directory):
                    os.makedirs(autosslscan_output_directory, exist_ok=True)

                command = f"python scripts/autosslscan.py -i {merger_output_path} -o {autosslscan_output_directory} -t 10"
                print(command)
                run_verbose_command(command)

                # http-get
                httpget_output_directory = "http-get-output"
                if not os.path.exists(f"{output_directory_name}/{ip_range_name}/{httpget_output_directory}"):
                    os.makedirs(f"{output_directory_name}/{ip_range_name}/{httpget_output_directory}")
                command = f"python scripts/http-get-improved.py -x {merger_output_path}"
                run_verbose_command_with_input(command, f"{output_directory_name}/{ip_range_name}/{httpget_output_directory}")
            else:
                raise Exception("No nmap_merger output file found")
        else:
            raise Exception("No nmap xml files found")


def cleanup(ips_and_names, temp_directory):
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

if __name__ == "__main__":
    main()