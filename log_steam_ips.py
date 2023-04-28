from scapy.all import *
import subprocess
import re
import json
import pathlib
import functools
from abc import ABC, abstractmethod
import time

ping_dns_name_regex = re.compile(r"^Pinging ([^ ]+) ")

class DNSLookup:
    __slots__ = ("dns_store_filename", "dns_store")

    def __init__(self, dns_store_filename):
        self.dns_store_filename = dns_store_filename
        dns_store_filepath = pathlib.Path(dns_store_filename)
        if dns_store_filepath.exists():
            with open(dns_store_filepath, "r") as f:
                self.dns_store = json.load(f)
        else:
            self.dns_store = {}

    @staticmethod
    def ping_ip(ip):
        if ip == "10.0.0.255":
            return "Pinging 10.0.0.255 with 1 bytes of data:"
        # https://discussions.apple.com/thread/7848602
        elif 224 <= int(ip.split(".", maxsplit=1)[0]) <= 239:
            return f"Pinging {ip} with 1 bytes of data:"

        try:
            ping_output = subprocess.check_output(("ping", "-a", ip, "-n", "1", "-l", "1")).decode("utf-8")
        except subprocess.CalledProcessError as e:
            return f"Pinging {ip} with 1 bytes of data:"

        return ping_output

    def lookup_dns_name(self, ip):
        dns_name = self.dns_store.get(ip)
        if dns_name is None:
            ping_output = DNSLookup.ping_ip(ip)
            match_obj = ping_dns_name_regex.match(ping_output.strip())
            if match_obj is None:
                raise RuntimeError(f"Could not find dns name! ping_output: {ping_output}")

            dns_name = match_obj.group(1)
            self.dns_store[ip] = dns_name
            with open(self.dns_store_filename, "w+") as f:
                json.dump(self.dns_store, f, indent=2)

        return dns_name

class BNLCPacket(ABC):
    __slots__ = ("data", "src", "dst", "sport", "dport", "timestamp", "session", "is_send")

    def __init__(self, data, src, dst, sport, dport, timestamp, session, is_send):
        self.data = data
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.timestamp = timestamp
        self.session = session
        self.is_send = is_send
        self.serialize()

    def serialize(self):
        packet_filepath = pathlib.Path(f"dumps/{self.session}/{self.timestamp}.bin")
        packet_filepath.parent.mkdir(parents=True, exist_ok=True)

        if not packet_filepath.is_file():
            with open(packet_filepath, "wb+") as f:
                f.write(self.data)

            packet_metadata_filepath = packet_filepath.with_suffix(".json")
            packet_metadata = {
                "src": self.src,
                "dst": self.dst,
                "sport": self.sport,
                "dport": self.dport,
                "timestamp": self.timestamp,
                "session": self.session,
                "is_send": self.is_send
            }

            with open(packet_metadata_filepath, "w+") as f:
                json.dump(packet_metadata, f, indent=2)

    @classmethod
    def from_packet(cls, packet, timestamp, session, is_send):
        return cls(packet[Raw].load, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, timestamp, session, is_send)

    @classmethod
    def from_file(cls, filename):
        with open(pathlib.Path(filename).with_suffix(".json"), "r") as f:
            packet_metadata = json.load(f)
            src = packet_metadata["src"]
            dst = packet_metadata["dst"]
            sport = packet_metadata["sport"]
            dport = packet_metadata["dport"]
            timestamp = packet_metadata["timestamp"]
            session = packet_metadata["session"]
            is_send = packet_metadata["is_send"]

        with open(filename, "rb") as f:
            data = f.read()

        return cls(data, src, dst, sport, dport, timestamp, session, is_send)

    #@property
    #@abstractmethod
    #def is_send(self):
    #    pass

class PacketCollector:
    __slots__ = ("packets", "send_packets", "recv_packets", "waiting_send_packets")

    def __init__(self):
        self.packets = []
        self.send_packets = []
        self.recv_packets = []
        self.waiting_send_packets = {}

    def add_packet(self, packet, timestamp, session, is_send):
        bnlc_packet = BNLCPacket.from_packet(packet, timestamp, session, is_send)
        self.packets.append(bnlc_packet)
        if is_send:
            self.send_packets.append(bnlc_packet)
            #self.waiting_send_packets[f"{bnlc_packet.src}:{bnlc_packet.sport} {bnlc_packet.dst}:{bnlc_packet.dport}"] = bnlc_packet
        else:
            self.recv_packets.append(bnlc_packet)

        return bnlc_packet

class SingletonState:
    __slots__ = ("session", "dns_lookup", "packet_collector")

    def __init__(self, session, dns_lookup, packet_collector):
        self.session = session
        self.dns_lookup = dns_lookup
        self.packet_collector = packet_collector

def is_valve_ip(state, ip):
    dns_name = state.dns_lookup.lookup_dns_name(ip)
    #print(f"dns_name: {dns_name}")
    return dns_name.endswith("valve.net")

def on_found_packet(state, packet):
    timestamp = time.time_ns()

    if IP not in packet:
        print(f"Not valve IP: {packet.summary()}")
    else:
        try:
            if is_valve_ip(state, packet[IP].src):
                state.packet_collector.add_packet(packet, timestamp, state.session, False)
                print(f"Found valve IP: {packet[IP].src}")
            elif is_valve_ip(state, packet[IP].dst):
                state.packet_collector.add_packet(packet, timestamp, state.session, True)
                print(f"Found valve IP: {packet[IP].dst}")
            else:
                print(f"Not valve IP: src: {packet[IP].src}, dst: {packet[IP].dst}")
        except Exception as e:
            raise RuntimeError(f"packet: {packet.show()}") from e

def main():
    dns_lookup = DNSLookup("dns_store.json")
    packet_collector = PacketCollector()

    state = SingletonState("session3", dns_lookup, packet_collector)

    on_found_packet_partial = functools.partial(on_found_packet, state)

    capture = sniff(filter="udp", count=0, prn=on_found_packet_partial)
    #print(capture[0])
    #for packet in capture:

if __name__ == "__main__":
    main()
