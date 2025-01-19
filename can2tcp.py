#!/usr/bin/env python3
import socket
from threading import Thread
from time import sleep
import can
import struct
import logging
import argparse

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class GatewayCanMessage():
    @staticmethod
    def pack(message: can.Message):
        flags = 0x00
        if message.is_extended_id:
            flags += 0x80
        if message.is_remote_frame:
            flags += 0x40
        packet  = struct.pack(">BI", flags | message.dlc, message.arbitration_id)
        packet += bytes(message.data)
        packet += bytes(8 - len(message.data))
        return packet

    @staticmethod
    def unpack(data):
        try:
            parsed_data = struct.unpack(">BI8B", data)
            res = can.Message()
            res.arbitration_id = parsed_data[1]
            res.data = parsed_data[2:10]
            res.dlc = parsed_data[0] & 0x0F
            if parsed_data[0] & 0x80:
                res.is_extended_id = True
            if parsed_data[0] & 0x40:
                res.is_remote_frame = True
            return res
        except:
            return None


class SocketCANGateway:
    def __init__(self, interface='vcan0', bitrate=1000000, receive_callback=None):
        self.interface = interface
        self.bitrate = bitrate
        self.receive_callback = receive_callback
        self.bus = can.interface.Bus(interface='socketcan', channel=self.interface, bitrate=self.bitrate)
        logger.info("Opened socket CAN interface {}".format(self.interface))
        self.runner_thread = Thread(name="socketcangateway_runner", target=self.runner, daemon=True)
        self.runner_thread.start()

    def set_receive_callback(self, receive_callback):
        self.receive_callback = receive_callback

    def runner(self):
        while True:
            msg = self.bus.recv()
            if self.receive_callback is not None:
                self.receive_callback(msg)

    def send(self, msg):
        if msg is not None:
            try:
                self.bus.send(msg)
            except:
                pass

class TCPCanGateway:
    def __init__(self, host=None, port=None, reconnect_interval=2, receive_callback=None):
        self.host = host
        self.port = port
        self.reconnect_interval = reconnect_interval
        self.receive_callback = receive_callback
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.runner_thread = Thread(name="tcpcangateway_runner", target=self.runner, daemon=True)
        self.runner_thread.start()

    def set_receive_callback(self, receive_callback):
        self.receive_callback = receive_callback

    def runner(self):
        while True:
            while not self.connected:
                try:
                    logger.info("Connecting to TCP Gateway at {}:{}".format(self.host, self.port))
                    if self.socket is None:
                        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.connect((self.host, self.port))
                    self.connected = True
                    logger.info("Connected to TCP Gateway")
                except socket.error:
                    logger.error("Error connecting to TCP Gateway")
                    sleep(self.reconnect_interval)
            while self.connected:
                try:
                    data = self.socket.recv(1024)
                    if data:
                        if self.receive_callback is not None:
                            for offset in range(0, len(data), 13):
                                self.receive_callback(GatewayCanMessage.unpack(data[offset:offset + 13]))
                    else:
                        logger.error("TCP socket no data error")
                        self.connected = False
                        self.socket = None
                except socket.error:
                    logger.error("TCP socket read error");
                    self.connected = False
                    self.socket = None

    def send(self, message):
        if message is not None and self.connected:
            try:
                packet = GatewayCanMessage.pack(message)
                self.socket.send(packet)
            except socket.error:
                self.connected = False
                self.socket = None


if __name__ == "__main__":
    logger.info('CAN2TCP gateway starting')
    parser = argparse.ArgumentParser(
        prog='can2tcp'
    )
    parser.add_argument('-i', '--interface', dest='interface', type=str, default='vcan0', help='CAN interface name')
    parser.add_argument('--host', dest='host', type=str, default='192.168.100.129', help='TCP gateway hostname/IP')
    parser.add_argument('--port', dest='port', type=int, default=20001, help='TCP gateway port')
    args = parser.parse_args()
    tcp_can_gateway = TCPCanGateway(args.host, args.port)
    socket_can_gateway = SocketCANGateway(interface=args.interface, bitrate=1000000)
    tcp_can_gateway.set_receive_callback(socket_can_gateway.send)
    socket_can_gateway.set_receive_callback(tcp_can_gateway.send)
    while True:
        sleep(5)
