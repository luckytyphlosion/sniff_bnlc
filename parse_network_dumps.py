import glob
from log_steam_ips import BNLCPacket
import pathlib
import shutil

def main():
    session = "session2"
    out_session = "dumps_matched"

    waiting_send_packets = {}
    pathlib.Path(f"dumps_matched/{session}").mkdir(parents=True, exist_ok=True)

    for packet_filename in glob.glob(f"dumps/{session}/*.bin"):
        bnlc_packet = BNLCPacket.from_file(packet_filename)
        if bnlc_packet.is_send:
            waiting_send_packets[f"{bnlc_packet.src}:{bnlc_packet.sport} {bnlc_packet.dst}:{bnlc_packet.dport}"] = bnlc_packet
        else:
            packet_key = f"{bnlc_packet.dst}:{bnlc_packet.dport} {bnlc_packet.src}:{bnlc_packet.sport}"
            matching_send_packet = waiting_send_packets.get(packet_key)
            if matching_send_packet is not None:
                waiting_send_packets[packet_key] = None
                timestamp = matching_send_packet.timestamp
                send_packet_basename = f"{timestamp}.bin"
                send_packet_filepath = pathlib.Path(f"dumps/{session}/{send_packet_basename}")
                send_packet_metadata_filepath = send_packet_filepath.with_suffix(".json")

                send_packet_new_filepath = pathlib.Path(f"dumps_matched/{session}/{timestamp}/send_{send_packet_filepath.name}")
                send_packet_metadata_new_filepath = send_packet_new_filepath.with_suffix(".json")

                recv_packet_filepath = pathlib.Path(packet_filename)
                recv_packet_metadata_filepath = recv_packet_filepath.with_suffix(".json")

                recv_packet_new_filepath = pathlib.Path(f"dumps_matched/{session}/{timestamp}/recv_{recv_packet_filepath.name}")
                recv_packet_metadata_new_filepath = recv_packet_new_filepath.with_suffix(".json")

                send_packet_new_filepath.parent.mkdir(parents=True, exist_ok=True)

                shutil.copyfile(send_packet_filepath, send_packet_new_filepath)
                shutil.copyfile(send_packet_metadata_filepath, send_packet_metadata_new_filepath)
                shutil.copyfile(recv_packet_filepath, recv_packet_new_filepath)
                shutil.copyfile(recv_packet_metadata_filepath, recv_packet_metadata_new_filepath)

if __name__ == "__main__":
    main()
