#!/ur/bin/env python
#coding:utf8
from gevent import wsgi
from gevent import pool
from gevent import monkey

monkey.patch_all()

import os,sys
import time
import cgi
import struct, socket
import json

from config import config
from traceback import format_exc
from multiprocessing import Process
from comm.deco import DecoLog
import logging
import redis
#logging.basicConfig()
import ast
import json
import MySQLdb

CUR_PATH = os.path.dirname(os.path.abspath(__file__)) 
sys.path.append(CUR_PATH+'/../cq_query/client/')
sys.path.append("/home/work/local/server_monitor/attr_api/")
import client
from comm.srf_log import logger, init_log, logger_d, logger_e
import errcode

#import service
import AgentModule

class Processor:
    def __init__(self):
        ##init log
        log_name = config.get_string("Log", "log_name", "gevent")
        log_level = config.get_string("Log", "log_level", "debug")
        init_log(log_path=CUR_PATH + "/../log", log_name=log_name, log_level=log_level)
        redis_ip=config.get_string("Server", "redis_ip")
        redis_port=config.get_int("Server", "redis_port")
        redis_p = redis.ConnectionPool(host=redis_ip, port=redis_port, db=0)
        self.conn = redis.StrictRedis(connection_pool=redis_p)

    @DecoLog()
    def parse_request(self,data):
        try:
            h=data
            total_len,w_save = struct.unpack("!IH", h[0:6])
            cur_len = 6
            (inner_header_len,) = struct.unpack("!I", h[cur_len : cur_len + 4])
            cur_len += 4
            
            inner_header_buf = h[cur_len:cur_len+inner_header_len]
            cur_len += inner_header_len
            
            (tmp_len,)= struct.unpack("!I", h[cur_len : cur_len + 4])
            cur_len += 4
            
            body_info = h[cur_len:]
            
            #return inner_header_buf, body_info
            return total_len,tmp_len
        except:
            logger_e.error("recv&parse packet failed: %s" % format_exc())
            return None, None

    @DecoLog()
    def get_upload_params(self,environ):
        """
            get POST Upload  parameters from request,
            return a dict "params" back.
        """
        fieldstorage = cgi.FieldStorage(fp = environ['wsgi.input'], environ = environ, keep_blank_values = True)
        field = fieldstorage.value
        if field==None:
            return None
        tl,ih=self.parse_request(field)
        AgentModule.AgentRepSum(3050, 1)
        if len(field)!=tl:
            AgentModule.AgentRepSum(3051, 1)
            return None
        #print tl
        #key = '58DAC89AA392C630'
        #IV='PKCS5Padding'
        #mode = AES.MODE_ECB
        #decryptor = AES.new(key, mode, IV=IV)
        #plain = decryptor.decrypt(ih)
        #nn = decryptor.decrypt(ib)
        #print "!!!!!!!!!!!!!!"
        return field

    @DecoLog()
    def build_response(self,data,ret):
        header_buf,body_buf=self.parse_request(data)
        header_all = pack("!HI",0,len(header_buf)) + header_buf
        body='"result":%d'%ret
        body_all = pack("!I",len(body)) + body
        total_buf = pack("!I", len(header_all)+len(body_all)+4) + header + body
        return total_buf
    @DecoLog()
    def start_process(self, environ, start_response):
        ##set HTTP response header
        status = '200 OK'
        response_headers = [('Content-type', 'text/html'), ('Connection', 'Keep-Alive')]
        ##send response
        start_response(status, response_headers)


        try:
            err_code = errcode.E_OK

            #client ip
            #str_cip = environ.get("REMOTE_ADDR", '0.0.0.0')
            str_cip = environ.get("HTTP_X_REAL_IP", '0.0.0.0')
            client_ip = struct.unpack("I", socket.inet_aton(str_cip))[0]

            ##get query parameters
            request_method = environ.get("REQUEST_METHOD")
            content_type = environ.get('CONTENT_TYPE')
            AgentModule.AgentRepSum(2922, 1)

            if request_method == None or content_type == None:
                AgentModule.AgentRepSum(2924, 1)
                return [self.get_response(errcode.E_FAIL)]
            
            if request_method == "POST":     # process post request
                # data report
                params = self.get_upload_params(environ)

                if params == None:
                    AgentModule.AgentRepSum(2926, 1)
                    return [self.get_response(errcode.E_OK)]

                err_code = self.handle_request( params, client_ip)
            else:
                logger_e.error("unknown request type: %s:%s from %s" % (request_method, content_type, str_cip))
                return [self.get_response(errcode.E_FAIL)]

            #build response package
            #response = self.get_response(err_code)
                
            #return [response]
            AgentModule.AgentRepSum(2923, 1)
            return [err_code]
        except:
            logger_e.error("Service response unknown exception from clientip %s %s environ=== %s" % (str_cip, format_exc(),environ))
            return [self.get_response(errcode.E_FAIL)]

    @DecoLog()
    def get_response(self,  err_code):
        '''
            get http response package
        '''
        res_dict={}
        res_dict['errcode']=-1
        errs=json.dumps(res_dict)
        #encrypt
        if err_code == errcode.E_OK:
            return errs
        elif err_code == errcode.E_EXIST:
            return errs
        elif err_code == errcode.E_UNPACK:
            return errs
        elif err_code == errcode.E_CHECK:
            return errs
        elif err_code == errcode.E_PARAM:
            return errs
        else:
            return errs

    @DecoLog()
    def check_request(self, header_dict):
        return True

    @DecoLog()
    def handle_request(self, tar_dict, client_ip):
        '''
            serviceid == 0:
            local process. Generate the session and return; 
            just header and no body

            serviceid == ***:
            decrypt and just transfer this package to backend
        '''
        res_dict={}
        res_dict['errcode']=-1
        try:
            self.conn.lpush('taskq',tar_dict)
            #addr_r=('10.205.27.53',9812)
            #real_s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            #real_s.sendto(tar_dict,addr_r)
            res_dict['errcode']=0
            return json.dumps(res_dict)
            logger_d.info("get dataupload and write to queue")
        except:
            logger_e.error(format_exc())
            AgentModule.AgentRepSum(2925, 1)
            return json.dumps(res_dict)

if __name__ == "__main__":
    # get pool_size and pid_file path
    try:
        ip = config.get_string("Server", "server_ip")
        port = config.get_int("Server", "server_port")
        processor_cnt = config.get_int("Server", "processor")
        pool_size = config.get_int("Server", "pool_size")
        pid_file = config.get_string("Server", "pid_file", CUR_PATH + "/../run/gevent.pid")
    except:
        print "Error config file!"
        exit(0)

    def put_pid_file(file_path):
        fd = open(file_path, 'a')
        pid = os.getpid()
        fd.write("%d\n" % pid)
        fd.close()

    def serve_forever(server):
        put_pid_file(pid_file)
        server.serve_forever()


    def process_upload(env, start_response):
        processor = Processor()
        return processor.start_process(env, start_response)


    pool = pool.Pool(pool_size)
    server = wsgi.WSGIServer((ip, port), process_upload, spawn = pool, log = None)
    server.pre_start()

    for i in range(processor_cnt - 1):
        Process(target=serve_forever, args=(server,)).start()

    serve_forever(server)
