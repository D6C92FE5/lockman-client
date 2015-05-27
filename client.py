# -*- coding: utf-8 -*-
import base64

import logging
import json
import hashlib
import os
import socket
import subprocess
from uuid import uuid4

from tornado.ioloop import IOLoop
from tornado.gen import coroutine
from tornado.tcpclient import TCPClient
from cryptography.fernet import Fernet, InvalidToken


def dumpb(o):
    return json.dumps(o).encode() + b'\n'


def loadb(b):
    return json.loads(b[:-1].decode())


class Client:

    default_config = {
        'locking-manager-bin': 'LockingManager',
        'device': uuid4().hex,
        'host': 'localhost',
        'port': 8888,
        'credentials': {}
    }

    def __init__(self, config_path='lockman-client.json', pair_mode=False):
        self.config = {}
        self.config_path = config_path
        self.ioloop = IOLoop.current()
        self.pair_mode = pair_mode

        self.load_config()
        self.ioloop.add_callback(self.connect)

    def load_config(self):
        path = self.config_path
        logging.info('load config from {}'.format(path))
        if os.path.exists(path):
            with open(path) as f:
                self.config = json.load(f)
        else:
            logging.warning('config file not found, use default config')
        for k, v in self.default_config.items():
            self.config.setdefault(k, v)
        self.dump_config()

    def dump_config(self):
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f)

    @coroutine
    def connect(self):
        stream = yield TCPClient().connect(self.config['host'], self.config['port'])
        yield stream.write(dumpb({'device': self.config['device'], 'name': socket.gethostname()}))
        stream = yield stream.start_tls(False)

        self.load_config()
        cert = stream.socket.getpeercert(True)
        fingerprint = hashlib.sha1(cert).hexdigest()

        request = loadb((yield stream.read_until(b'\n')))
        request['cert'] = cert
        request['device'] = fingerprint
        result = getattr(self, 'handle_' + request['command'])(request)
        yield stream.write(dumpb(result))

        stream.set_close_callback(self.connect)
        stream.close()

    def handle_pair(self, request):
        print("请求配对的控制设备的识别指纹为 {}".format(request['device']))
        if input("此识别指纹是否与控制设备上显示的一致？(Y/N)").upper() != 'Y':
            return {'message': "配对请求被拒绝"}

        username = input("请输入帐号：")
        password = input("请输入密码：")
        credential = json.dumps([username, password])

        encrypted = self._get_credential_fernet(request['cert']).encrypt(credential.encode())
        self.config['credentials'][request['device']] = encrypted.decode()
        self.dump_config()

        return {'message': "配对成功"}

    def handle_status(self, request):
        if request['device'] not in self.config['credentials']:
            return {'error': "未配对"}
        lockman = self.config['locking-manager-bin']
        result = subprocess.check_output([lockman, 'status'])
        return {'status': result.decode()[:-1]}

    def handle_lock(self, request):
        if request['device'] not in self.config['credentials']:
            return {'error': "未配对"}
        lockman = self.config['locking-manager-bin']
        result = subprocess.check_output([lockman, 'lock'])
        return {'status': result.decode()}

    def handle_unlock(self, request):
        if request['device'] not in self.config['credentials']:
            return {'error': "未配对"}
        lockman = self.config['locking-manager-bin']
        encrypted = self.config['credentials'][request['device']].encode()
        try:
            credential = self._get_credential_fernet(request['cert']).decrypt(encrypted)
        except InvalidToken:
            return {'error': "请重新配对"}
        credential = json.loads(credential.decode())
        try:
            result = subprocess.check_output([lockman, 'unlock'] + credential)
        except subprocess.CalledProcessError as ex:
            # 调用失败时返回错误代码
            return {'message': "解锁失败，错误代码 {}".format(ex.returncode)}
        else:
            return {'message': "解锁成功"}

    def _get_credential_fernet(self, cert):
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(cert).digest()))


if __name__ == '__main__':
    Client()
    IOLoop.instance().start()
