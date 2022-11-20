from socket import *
import json
import struct
import sys
import hashlib
import time
from os.path import getsize
import argparse
from tqdm import tqdm

OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]
    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


(ip, student_id, fpath) = sys.argv[0], sys.argv[0], sys.argv[0]

password = hashlib.md5('2037025'.encode('utf-8')).hexdigest().lower()
def parse():
    parse = argparse.ArgumentParser()
    parse.add_argument("-server_ip", default='', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("-port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("-id", default='1379', action='store', required=False, dest="id",
                       help="id")
    parse.add_argument("-f", default='', action='store', required=False, dest="path",
                       help="The port that server listen on. Default is 1379.")
    return parse.parse_args()

HOST = parse().ip
POST = parse().port
ADDR = (HOST, POST)

with open(fpath, 'rb') as f:
    b_data = f.read()


size = getsize(fpath)

with socket(AF_INET, SOCK_STREAM) as s:
    s.connect((HOST,int(POST)))
    print('connect！！！')

    j_data_login = {"type": "AUTH", "operation": "LOGIN", "direction": "REQUEST", "size": size,
                    "username": '2037025', "password": password}
    message_login = make_packet(j_data_login, b_data)
    s.send(message_login)
    token = get_tcp_packet(s)[0]['token']
    print(f'Token: {token}')

    j_data_save = {"type": "FILE", "operation": "SAVE", "direction": "REQUEST", "size": size, "token": token}
    message_save = make_packet(j_data_save, b_data)
    s.send(message_save)
    response = get_tcp_packet(s)[0]
    key = response['key']
    total_block = response['total_block']
    block_size = response['block_size']

    start_time = time.time()

    for i in tqdm(range(total_block)):
        j_data_upload = {"type": "FILE", "operation": "UPLOAD", "direction": "REQUEST",
                         "size": size, "block_index": i, "key": key, "token": token}
        message_upload = make_packet(j_data_upload, b_data[block_size*i: block_size*(i+1)])
        s.send(message_upload)
        response,_ = get_tcp_packet(s)
        #print(response['status_msg'])
        

    total_time = time.time() - start_time

    file = open('E:/f.txt', 'rb').read()
    file_md5 = hashlib.md5(file).hexdigest()
    if file_md5 == str(response[FIELD_MD5]):
        print('successfull transfer.')
    print(f'The file[{fpath}] is uploaded! ')

    # def progress(percent):
    #     if percent > 1:
    #         percent = 1
    #     res = int(50 * percent) * '#'
    #     print('\r[%-50s] %d%% ' % (res, int(100 * percent)), end='')
    #
    # recv_size = 0
    # total_size = 1025011
    #
    # while recv_size < total_size:
    #     time.sleep(0.01)
    #
    #     recv_size += 1024
    #
    #     percent = recv_size / total_size
    #     progress(percent)

    print("\n total_time is",total_time,'s')
