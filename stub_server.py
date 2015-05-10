# -*- coding: utf-8 -*-


from tornado.ioloop import IOLoop
from tornado.gen import coroutine
from tornado.tcpserver import TCPServer

from client import dumpb, loadb


class StubServer(TCPServer):
    @coroutine
    def handle_stream(self, stream, address):
        response = loadb((yield stream.read_until(b'\n')))
        print(response)
        stream = yield stream.start_tls(True, {
            'keyfile': 'cert/tls.key', 'certfile': 'cert/tls.crt'})
        yield stream.write(dumpb({'command': 'unlock'}))
        response = loadb((yield stream.read_until(b'\n')))
        print(response)
        print()

StubServer().listen(8888)
IOLoop.instance().start()
