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
reload(sys)
sys.setdefaultencoding('utf-8')

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
import re
from Crypto.Cipher import AES

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
        conn = MySQLdb.connect(host='10.52.164.22',user='root',passwd='',db='user_feedback')
        self.cursor = conn.cursor()
    @DecoLog()
    def parse_request(self,data):
        try:
            if len(data)<6:
                return None, None
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
            
            return inner_header_buf, body_info
        except:
            logger_e.error("recv&parse packet failed: %s" % format_exc())
            AgentModule.AgentRepSum(2910, 1)
            return None, None


    @DecoLog()
    def get_upload_params(self,environ):
        """
            get POST Upload  parameters from request,
            return a dict "params" back.
        """
        fieldstorage = cgi.FieldStorage(fp = environ['wsgi.input'], environ = environ, keep_blank_values = True)
        field = fieldstorage.value
        try:
            ih,ib=self.parse_request(field)
            if ih==None or ib==None:
                return None,None
            key = '58DAC89AA392C630'
            IV='PKCS5Padding'
            mode = AES.MODE_ECB
            decryptor = AES.new(key, mode, IV=IV)
            plain = decryptor.decrypt(ih)
            n_body = decryptor.decrypt(ib)
            return plain,n_body
        except:
            logger_e.error("jiemi packet failed: %s" % format_exc())
            AgentModule.AgentRepSum(2911, 1)
            return None,None
    @DecoLog()
    def build_inner_header(self, cmd_id, sub_cmd_id):
        header = inner_header_pb2.InnerHeader()
        header.cmd = cmd_id
        header.subcmd = sub_cmd_id
        header.seq = 0
        header.protoversion = 1
        header_buf = header.SerializeToString()
        header_all = pack("!IH", len(header_buf), const.TYPE_INNERHEADER) + header_buf
        return header_all
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
            AgentModule.AgentRepSum(2907, 1)

            if request_method == None or content_type == None:
                return [self.get_response(errcode.E_FAIL)]
            
            if request_method == "POST":     # process post request
                # data report
                params,body = self.get_upload_params(environ)

                if params == None or body==None:
                    return [self.get_response(errcode.E_OK)]

                err_code = self.handle_request( params, body)
            else:
                logger_e.error("unknown request type: %s:%s from %s" % (request_method, content_type, str_cip))
                AgentModule.AgentRepSum(2909, 1)
                return [self.get_response(errcode.E_FAIL)]

            #build response package
            #response = self.get_response(err_code)
                
            #return [response]
            AgentModule.AgentRepSum(2908, 1)
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
    def handle_request(self, tar_dict, client_body):
        
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
            mylist=[]
            #post_dict=ast.literal_eval(tar_dict.strip())
            #b_dict=ast.literal_eval(client_body.strip())
            h_str=re.findall('({.*}).*',tar_dict)[0]
            b_str=re.findall('({.*}).*',client_body)[0]
            post_dict=json.loads(h_str)
            b_dict=json.loads(b_str)
            if len(post_dict)!=14:
                AgentModule.AgentRepSum(2912, 1)
                return json.dumps(res_dict)
            if len(b_dict)!=3:
                AgentModule.AgentRepSum(2912, 1)
                return json.dumps(res_dict)
            for k,v in post_dict.items():
                post_dict[k]=MySQLdb.escape_string(v)
            for k,v in b_dict.items():
                b_dict[k]=MySQLdb.escape_string(v)

            device_id=post_dict['1']
            os_version=post_dict['2']
            xinghao=post_dict['3']
            zhizaoshang=post_dict['4']
            language=post_dict['5']
            country=post_dict['6']
            soft_version=post_dict['7']
            mac_addr=post_dict['8']
            ip_addr=post_dict['9']
            qudao=post_dict['10']
            yunyingshang=post_dict['11']
            fenbianlv=post_dict['12']
            soft_id=post_dict['13']
            service_id=post_dict['14']


            datet=b_dict['1']
            email=b_dict['2']
            content=b_dict['3']
            sql = 'insert into `feedback` values(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")'%(email,os_version,xinghao,device_id,soft_id,content,language,country,zhizaoshang,datet,soft_version,mac_addr,ip_addr,qudao,yunyingshang,fenbianlv,service_id)
            self.cursor.execute(sql)
            res_dict['errcode']=0
            logger_d.info("get request and insert to sql")
            return json.dumps(res_dict) 
        except:
            logger_e.error(format_exc())
            AgentModule.AgentRepSum(2913, 1)
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
