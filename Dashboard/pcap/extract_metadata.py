import argparse
import csv
import shutil
import subprocess
from pathlib import Path


TSHARK_PATH = Path(r"C:\Program Files\Wireshark\tshark.exe")

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "udp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "udp.dstport",
    "frame.protocols",
]


def find_tshark():
    """Return the available TShark executable."""
    if TSHARK_PATH.is_file():
        return str(TSHARK_PATH)

    installed_path = shutil.which("tshark")
    if installed_path:
        return installed_path

    raise FileNotFoundError(
        "TShark was not found. Check the Wireshark installation."
    )


def extract_metadata(pcap_path, output_path):
    """Extract packet metadata from a PCAPNG file into a CSV."""
    pcap_path = Path(pcap_path).resolve()
    output_path = Path(output_path).resolve()

    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tshark = find_tshark()

    command = [
        tshark,
        "-n",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(
            [
                "pcap_filename",
                "frame_number",
                "timestamp_epoch",
                "src_ip",
                "src_port",
                "dest_ip",
                "dest_port",
                "protocols",
            ]
        )

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        reader = csv.reader(process.stdout)

        try:
            for row in reader:
                if len(row) != len(FIELDS):
                    continue

                frame_number, timestamp = row[0], row[1]
                src_ip = row[2] or row[3]
                src_port = row[4] or row[5]
                dest_ip = row[6] or row[7]
                dest_port = row[8] or row[9]
                protocols = row[10]

                writer.writerow(
                    [
                        pcap_path.name,
                        frame_number,
                        timestamp,
                        src_ip,
                        src_port,
                        dest_ip,
                        dest_port,
                        protocols,
                    ]
                )
        finally:
            process.stdout.close()

        stderr_output = process.stderr.read()
        return_code = process.wait()

        if return_code != 0:
            output_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"TShark failed with exit code {return_code}:\n"
                f"{stderr_output}"
            )

    print(f"Metadata saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract packet metadata from a PCAPNG file."
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the input PCAP or PCAPNG file.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path. Defaults to data/pcap_metadata/<filename>.csv",
    )

    args = parser.parse_args()

    pcap_path = Path(args.pcap_file)
    output_path = (
        Path(args.output)
        if args.output
        else Path("data")
        / "pcap_metadata"
        / f"{pcap_path.stem}.csv"
    )

    extract_metadata(pcap_path, output_path)

if __name__ == "__main__":
    main()