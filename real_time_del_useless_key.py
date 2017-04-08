#!/usr/bin/env python
#encoding:utf-8

#monkey patch
from gevent import monkey
monkey.patch_all(dns=False)
import sys, os
import socket
import struct
import traceback
import logging
logging.basicConfig()
from gevent.queue import Queue, Empty
import gevent
import redis

#gevent
from gevent import pool
from gevent.server import StreamServer, DatagramServer
from gevent import Timeout
from multiprocessing import Process

#proto
from proto import inner_header_pb2
from proto import scan_result_pb2

#log and config
from config import config
from comm.srf_log import logger,init_log,logger_d,logger_e
from comm.deco import DecoLog

CUR_PATH = os.path.dirname(os.path.abspath(__file__))

class Processor:
    def __init__(self):
        """init  variables"""
        #init log
        log_name = config.get_string("Log", "log_name", "gevent")
        log_level = config.get_string("Log", "log_level", "debug")
        init_log(log_path=CUR_PATH + "/../log", log_name=log_name, log_level=log_level)

        self.recv_timeout = config.get_int("Server", "recv_timeout", 10)

        #init redis connection
        redis_ip_str = config.get_string("Redis", "ip")
        redis_port_str = config.get_string("Redis", "port")
        redis_ip_list = redis_ip_str.split(',')
        redis_ip_list = [ip.strip() for ip in redis_ip_list]
        redis_port_list = redis_port_str.split(',')
        redis_port_list = [int(port.strip()) for port in redis_port_list]

        self.redis_conn_list = []
        for i in xrange(len(redis_ip_list)):
            redis_conn = redis.StrictRedis(host=redis_ip_list[i],port=redis_port_list[i], db=0)
            self.redis_conn_list.append(redis_conn)
    
    @DecoLog()
    def _parse_request(self, data):
        '''
            packet = dwTotalLen + dwInnerHeaderLen + wType + InnerHeader + dwBodyTotalLen + wType + Info
        '''
        try:
            h = data[0:4]
            total_len = struct.unpack("!I", h)[0]
            
            h = data[4:]
             
            cur_len = 0
            inner_header_len, w_type = struct.unpack("!IH", h[cur_len : cur_len + 6])
            cur_len += 6
            
            inner_header_buf = h[cur_len:cur_len+inner_header_len]
            cur_len += inner_header_len
            
            tmp_len, tmp_type= struct.unpack("!IH", h[cur_len : cur_len + 6])
            cur_len += 6
            
            body_info = h[cur_len:]
            
            return inner_header_buf, body_info
        except :
            logger_e.error("recv&parse packet failed: %s" % traceback.format_exc())
            return None, None

    def _del_md5_in_redis(self, md5):
        try:
            for conn in self.redis_conn_list:
                search_key = 'search_%s' % md5
                merge_key = 'merge_%s' % md5
                conn.delete(search_key, merge_key)
            logger.info('succ delete md5: %s' % md5)
        except:
            logger.error("delete md5 in redis error: %s" % traceback.format_exc())

    def _handle_packet_from_global_collector(self, info_buf):
        try:
            scan_result = scan_result_pb2.ScanResult()
            scan_result.ParseFromString(info_buf)
            logger.info("get global collector packet, md5: %s" % (scan_result.md5))
            #从cache中删除这个md5
            self._del_md5_in_redis(scan_result.md5)
        except:
            logger_e.error("handle packet from global collector failed: %s" % traceback.format_exc())
            return

    @DecoLog()
    def __call__(self, data, address):
        try:
            #recv and parse request
            inner_header_buf, info_buf = self._parse_request(data)
            if inner_header_buf == None or info_buf == None:
                return
            
            inner_header = inner_header_pb2.InnerHeader()
            inner_header.ParseFromString(inner_header_buf)

            if inner_header.cmd == 171: #只处理从global collector转过来的包
                self._handle_packet_from_global_collector(info_buf)
        except:
            logger_e.error("process error: %s" % traceback.format_exc())
    
if __name__ == "__main__":

    def put_pid_file():

        #write the pid file
        pid_file = config.get_string("Server", "pid_file", CUR_PATH + "/../run/gevent.pid")

        fd = open(pid_file, 'a')
        pid = os.getpid()
        fd.write("%d\n" % pid)
        fd.close()

    def serve_forever(server):
        put_pid_file()
        server.serve_forever()

   
    #get configuration
    server_ip = config.get_string("Server", "ip_addr", "0.0.0.0")
    server_port = config.get_int("Server", "port", 23620)
    pool_size = config.get_int("Server", "processor_pool_size", 4)

    processor = Processor()

    pool = pool.Pool(pool_size)
    server = DatagramServer((server_ip, server_port), processor, spawn = pool)
    #server.max_accpet = 10000
    server.start()

    process_count = config.get_int("Server", "processor")

    #for i in range(process_count - 1):
    #    Process(target=serve_forever, args=(server,)).start()

    serve_forever(server)
