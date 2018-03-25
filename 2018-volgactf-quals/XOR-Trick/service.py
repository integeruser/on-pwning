#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import logging
import argparse
import socket
import socketserver
from io import BytesIO
from PIL import Image
import numpy as np
from xtproc import process


MAX_INPUT_SIZE = 0x100000


"""
    Utils
"""


class InputOverflowException(Exception):
    pass


class InputUnderflowException(Exception):
    pass


def read_message(s, max_input_length=MAX_INPUT_SIZE):
    received_buffer = s.recv(8)
    if len(received_buffer) < 8:
        raise InputUnderflowException('Failed to receive data: the received length is less than 8 bytes long')

    to_receive = int.from_bytes(received_buffer[0:8], byteorder='little', signed=False)
    if to_receive > max_input_length:
        raise InputOverflowException('Failed to receive data: requested to accept too much data')
    received_buffer = b''

    while len(received_buffer) < to_receive:
        data = s.recv(to_receive - len(received_buffer))
        if len(data) == 0:
            raise InputUnderflowException('Failed to receive data: the pipe must have been broken')
        received_buffer += data
        if len(received_buffer) > max_input_length:
            raise InputOverflowException('Failed to receive data: accepted too much data')

    return received_buffer


def send_message(s, message):
    send_buffer = len(message).to_bytes(8, byteorder='little', signed=False) + message
    s.sendall(send_buffer)


class ForkingTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.TCPServer.server_bind(self)


class ServiceHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        logger.info('Accepted connection from {0}'.format(self.client_address[0]))
        try:
            self.request.settimeout(30)

            # greetings
            send_message(self.request, 'Welcome to the XOR trickery! Powered by {0}'
                         .format(sys.version).encode('utf-8'))
            send_message(self.request, b'Send your image file and stego message.')

            # accept image and data
            logger.debug('Reading the data')
            im_file_data = read_message(self.request)
            data = read_message(self.request)

            # process and send the result back
            logger.debug('Transforming the data')
            im = Image.open(BytesIO(im_file_data))
            im_arr = np.fromstring(im.tobytes(), dtype=np.uint8)
            image = im_arr.reshape((im.size[1], im.size[0], 3))

            logger.debug('Processing the data')
            stego_image = process(image, data)

            logger.debug('Returning the data')
            im = Image.fromarray(stego_image, 'RGB')
            fd = BytesIO()
            im.save(fd, format='png')
            stego_bytes = fd.getvalue()
            send_message(self.request, stego_bytes)

        except Exception as ex:
            logger.error(str(ex), exc_info=True)
            try:
                send_message(self.request, bytes('Failed to process the image: {0}'.format(ex).encode('utf-8')))
            except:
                pass

        finally:
            logger.info('Processed connection from {0}'.format(self.client_address[0]))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', type=str, default='0.0.0.0', help='Service IP address.')
    parser.add_argument('--port', type=int, default=45678, help='Service port.')
    args = parser.parse_args()

    logger = logging.getLogger(__name__)
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG)
    server = ForkingTCPServer((args.address, args.port), ServiceHandler)
    logging.info('Xor trick server is listening...')
    server.serve_forever()
