import os

PROGRAM = "./trace-Darwin-arm"

GOLD_OUTPUT_FILE_DIR = "CPE4464_p1_files"
pcap_files = [
    "ArpTest",
    "IP_bad_checksum",
    "largeMix",
    "largeMix2",
    "PingTest",
    "smallTCP",
    "TCP_bad_checksum",
    "UDPfile"
]

all_pass = True

for pcap_file in pcap_files:
    print(f"Running trace.py on {pcap_file}...")
    output_file = f"out_{pcap_file}.txt"
    pcap_filename = f"{GOLD_OUTPUT_FILE_DIR}/{pcap_file}.pcap"
    if not os.path.exists(pcap_filename):
        print(f"Error: {pcap_filename} does not exist.")
        continue
    command = f"{PROGRAM} {pcap_filename} > {output_file}"
    os.system(command)

    gold_output_file = f"{GOLD_OUTPUT_FILE_DIR}/{pcap_file}.out.txt"
    if not os.path.exists(gold_output_file):
        print(f"Error: {gold_output_file} does not exist.")
        continue
    diff_file = f"diff_{pcap_file}.txt"
    diff_cmd = f"diff {output_file} {gold_output_file} > {diff_file}"
    ret_val = os.system(diff_cmd)
    if ret_val != 0:
        all_pass = False
        print(f"Output for {pcap_file} does not match gold output. See {diff_file} for details.")
    else:
        os.remove(diff_file)

if all_pass:
    print("All tests passed!")
    for pcap_file in pcap_files:
        output_file = f"out_{pcap_file}.txt"
        os.remove(output_file)