#!/usr/bin/env python
#encoding:utf-8

#monkey patch
from gevent import monkey
monkey.patch_all(dns=False)
import sched
import sys, os
import socket
import binascii
import hashlib
import zipfile
import struct
import pymongo
import time
import traceback
import errcode
import errno
import StringIO
import redis
from datetime import datetime
import logging
#logging.basicConfig()
from gevent.queue import Queue, Empty
import gevent
import json
#import mail

#gevent
from gevent import pool
from gevent.server import StreamServer
from gevent import Timeout
from multiprocessing import Process

#proto
from proto import file_upload_pb2
from proto import inner_header_pb2
from proto import notice_dispatcher_pb2
from proto import notice_dc_pb2
from proto import dba_path_info_pb2
from proto import dba_basic_info_pb2
from proto import dba_pe_info_pb2
from proto import dba_url_info_pb2

#PE Parser
from pe import pe_parser,pefile

#log and config
from comm.server_frame_src.config import  config
from comm.srf_log import logger,init_log,logger_d,logger_e
from comm.deco import DecoLog
import const

#for test the run time
from time import clock

#other lib
import AgentModule
from mola_serve import mola_set
from mola_serve import mola_addAddress

import nope_parser
import bcs_serve

from ctypes import c_ulonglong as ull 
from ctypes import c_ubyte as ub
import bos_sample_conf
from baidubce import exception
from baidubce.services.bos import canned_acl
from baidubce.services.bos.bos_client import BosClient
CUR_PATH = os.path.dirname(os.path.abspath(__file__))
DSTPATH = os.path.join(CUR_PATH, "../files/target")
READPATH = os.path.join(CUR_PATH, "../files/little")
bos_client = BosClient(bos_sample_conf.config)
class UDPSender(object):
    def __init__(self, server, port):
        #udp sockets
        self.dst_ip = server
        self.port = port
        
    def send_udp_packets(self, buf, buf_len):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(buf, (self.dst_ip, self.port))
        except:
            logger_e.error("send udp packet failed. %s" % traceback.format_exc())
            sock.close()
            return errcode.E_NET_IO
        sock.close()

        return errcode.E_OK
        
class Report:
    QUERY_CNT = 881
    QUERY_SUCC = 889
    
    E_BAD_PE = 886
    E_MD5_CHECK_FAIL = 884
    E_ZIP_FAIL = 885
    E_REQUEST_PACKET_FAIL = 882
    E_OTHER_FAIL = 887
    E_WRITE_DB_FAIL = 894
    E_PARSER_REQUEST_FAIL = 883
    E_WRITE_MOLA = 636
    
    RE_UPLOAD = 888
    MERGE_SUCC = 890
    MERGE_ERROR = 891
    WRITE_LOCAL_ERROR = 895
    BLOCK_SUCC = 896
    
    X_QUERY_CNT = 646
    X_QUERY_SUCC_CNT = 897
    AURORA_QUERY_CNT = 227
    AURORA_QUERY_SUCC_CNT = 898
    OFFLINE_QUERY_CNT = 228
    OFFLINE_QUERY_SUCC_CNT = 899
    
    E_WRITE_BCS_FAIL = 892
    BIGPE_CNT = 1161
    APK_CNT = 1277
    
    def __init__():
        pass

class FileProcessor:
    def __init__(self, bcs):
        """init  variables"""
        #init server
        self.dp_server = config.get_string("Server", "dispatcher_server_ip")
        self.dp_port = config.get_int("Server", "dispatcher_server_port")

        self.dc_server = config.get_string("Server", "datacenter_server_ip")
        self.dc_port = config.get_int("Server", "datacenter_server_port")

        self.bp_dc_server = config.get_string("Server", "bp_datacenter_server_ip")
        self.bp_dc_port = config.get_int("Server", "bp_datacenter_server_port")
        self.bp_dp_server = config.get_string("Server", "bp_dispatcher_server_ip")
        self.bp_dp_port = config.get_int("Server", "bp_dispatcher_server_port")


        self.apk_dp_server = config.get_string("Server", "apk_dispatcher_server_ip")
        self.apk_dp_port = config.get_int("Server", "apk_dispatcher_server_port")
        self.apk_dc_server = config.get_string("Server", "apk_datacenter_server_ip")
        self.apk_dc_port = config.get_int("Server", "apk_datacenter_server_port")
        self.apk_dba_server = config.get_string("Server", "apk_dba_server_ip")
        self.apk_dba_port = config.get_int("Server", "apk_dba_server_port")

        self.pesummary_server = config.get_string("Server", "pesummary_server_ip")
        self.pesummary_port = config.get_int("Server", "pesummary_server_port")

        self.url_dba_server = config.get_string("Server", "url_dba_server_ip")
        self.url_dba_port = config.get_int("Server", "url_dba_server_port")
        
        self.redis_server = json.loads(config.get_string("Server", "redis_server_ip"))
        self.redis_port = json.loads(config.get_string("Server", "redis_server_port"))
        self.file_level = config.get_int("Server", "file_level")
        #print self.redis_server
        #print self.redis_port
        self.redis_conn_list = []
        #for redis_ip in self.redis_server:
        for i in range(len(self.redis_server)):
            redis_conn = redis.StrictRedis(host=self.redis_server[i], port=int(self.redis_port[i]), db=0)
            #print self.redis_server[i],self.redis_port[i]
            self.redis_conn_list.append(redis_conn)

        self.dba_server = config.get_string("Server", "dba_server_ip")
        self.dba_port = config.get_int("Server", "dba_server_port")
        self._bcs = bcs

        #init log
        log_name = config.get_string("Log", "log_name", "gevent")
        log_level = config.get_string("Log", "log_level", "debug")
        init_log(log_path=CUR_PATH + "/../log", log_name=log_name, log_level=log_level)

        self.recv_timeout = config.get_int("Server", "recv_timeout", 10)
        #self.mola_retry = config.get_int("Server", "mola_retry", 3)
    @DecoLog()
    def _binbuffromhex(self, hexbuf):
        binbuf = ""
        for i in range(16):
            binbuf = binbuf + struct.pack('B', int(hexbuf[i<<1], 16) << 4 | int(hexbuf[(i<<1)+1], 16))
        return binbuf
    @DecoLog()
    def _bos_get_bucket(self,file_md5):
        binbuf = self._binbuffromhex(file_md5)
        bin_st = struct.unpack('4I', binbuf)
        key = bin_st[0] ^ bin_st[1] ^ bin_st[2] ^ bin_st[3]
        key_index = key % 4000 + 1
        return "sw-sample-%04d" % (key_index)
    @DecoLog()
    def _get_redis_num(self, md5):
        file_md5 = md5.lower()
        binbuf = self._binbuffromhex(file_md5)
        bin_st = struct.unpack('8H', binbuf)
        #key_index = bin_st[0] % 8
        key_index = bin_st[0] % len(self.redis_server)
        #print key_index
        return key_index 
    @DecoLog()
    def _data_decrypt(self, file_body):
        enkey = 7656587
        nseed = enkey
        uvalue = ull(nseed)
        new_file_body = ""
        for i in range(0, len(file_body)):
            if i % 1024 == 0:
                uvalue = ull(nseed)
            uvalue = ull(uvalue.value * 6364136223846793005L + 1)
            rnd = ub(uvalue.value >> 19).value & 0xff
            new_file_body = new_file_body + chr(ub(struct.unpack('B', file_body[i])[0] ^ (enkey >> ((i%4)*8) & 0x000000ff) ^ rnd).value)
        return new_file_body
    def _del_file(self,md5_str,file_num,file_info):     
         try:
             list_m=[]
             cur_path=READPATH
             for i in xrange(0,len(md5_str),2):
                 list_m.append(md5_str[i:i+2])
             for i in xrange(self.file_level):
                 cur_path=os.path.join(cur_path,list_m[i])
             temp_list=[]
             for i in xrange(file_num):
                 temp_list.append(''.join([md5_str,'_',str(i)]))
             for tar_file in temp_list:
                 file_path=os.path.join(cur_path,tar_file)
                 if os.path.exists(file_path):
                     os.remove(file_path)
         except:
             logger_e.error("del file error %s" % traceback.format_exc())

    @DecoLog()
    def _merge_file(self,md5_str,file_num,file_info):     
         #start_time=time.time()
         #handle already exists file
         try:
             list_m=[]
             cur_path=READPATH
             for i in xrange(0,len(md5_str),2):
                 list_m.append(md5_str[i:i+2])
             for i in xrange(self.file_level):
                 cur_path=os.path.join(cur_path,list_m[i])
             #file_list=os.listdir(cur_path)
             temp_list=[]
             for i in xrange(file_num):
                 temp_list.append(''.join([md5_str,'_',str(i)]))
             if not os.path.exists(DSTPATH):
                 os.makedirs(DSTPATH)
             dst_path=os.path.join(DSTPATH,md5_str)
             dst_file=open(dst_path,'w+')
             content_buf=""
             #for tar_file in sorted_list:
             for tar_file in temp_list:
                 file_path=os.path.join(cur_path,tar_file)
                 lfile=open(file_path)
                 littfile_buf=lfile.read()
                 dst_file.write(littfile_buf)
                 content_buf=content_buf+littfile_buf
                 lfile.close()
             dst_file.close()
             file_info['file_body']=content_buf
             createfile_md5= hashlib.md5(content_buf).hexdigest()
             #print createfile_md5
             if (createfile_md5!=md5_str):
                 logger_d.info("merge file %s is not match with client" % md5_str) 
                 os.remove(dst_path)
                 for tar_file in temp_list:
                     file_path=os.path.join(cur_path,tar_file)
                     if os.path.exists(file_path):
                         os.remove(file_path)
                 return False
             return True
         except:
             logger_e.error("merge file error %s" % traceback.format_exc())
         finally:
             for tar_file in temp_list:
                 file_path=os.path.join(cur_path,tar_file)
                 if os.path.exists(file_path):
                     os.remove(file_path)
             
             
         #end_time=time.time()
         #delta_time = int((end_time - start_time)*1000000)
         #logger_d.info("merge file %s costs time %d" % (md5_str,delta_time))
         #print "merge file % tongji costs time %d" % (md5_str,delta_time)
    @DecoLog()
    def _write_file_tolocal(self,file_info):
        name=file_info['md5']
        buf=file_info['block_file_body']
        index=file_info['index']
        list_m=[]
        cur_path=READPATH
        #print name
        for i in xrange(0,len(name),2):
            list_m.append(name[i:i+2])
        for i in xrange(self.file_level):
            cur_path=os.path.join(cur_path,list_m[i])
        #fir_two=name[0:2]
        #sec_two=name[2:4]
        #fir_path=os.path.join(folder,fir_two)
        #sec_path=os.path.join(fir_path,sec_two)
            
        tar_file=os.path.join(cur_path,name+"_"+str(index))
        if not os.path.exists(cur_path):
            os.makedirs(cur_path)
        if os.path.exists(tar_file):
            return True
        try:    
            temp_file=open(tar_file,"w")
            temp_file.write(buf)
            temp_file.close()
            logger_d.info("write local file %s" % name+"_"+str(index))
            return True
        except:
            logger_e.error("write to local exception: %s" % traceback.format_exc())
            return False
    @DecoLog()
    def _write_file_to_mola(self, file_info):
        try:
            if mola_set(file_info['md5'], file_info['file_body']) == False:
                logger_e.error("store mola error: md5 %s" % file_info['md5'])
                file_info['file_exist_flag'] = 2
                return errcode.E_MOLA
            else:
                logger.debug('store mola succ: %s' % file_info['md5'])
                file_info['file_exist_flag'] = 1
                return errcode.E_OK
        except:
            logger_e.error("store mola exception: %s" % traceback.format_exc())
            file_info['file_exist_flag'] = 2
            return errcode.E_MOLA
    @DecoLog()
    def _write_file_to_bos(self, file_info):
        try:
            bucket = self._bos_get_bucket(file_info["md5"])
            bos_client.put_object_from_string(bucket,file_info["md5"], file_info["file_body"])
            logger_d.info("bos set success md5:%s to bucket:%s, body_len:%d" % (file_info["md5"], bucket, len(file_info["file_body"])))
        except:
            logger_e.error("bos put failed :%s" %  traceback.format_exc() )
            

    @DecoLog()
    def _write_file_to_bcs(self, file_info):
        #logger_d.info("put file_info to queue, md5:%s" % file_info["md5"])
        #self._queue.put(file_info)    
        bucket = bcs_serve.bcs_get_bucket(file_info["md5"])
        err = 0
        #with Timeout(5, False) as timeout:
        err = bcs_serve.bcs_put(self._bcs, bucket, file_info["md5"], file_info["file_body"])
        if err != errcode.E_BCS_OK:
            logger_e.error("bcs put failed :%s" %  traceback.format_exc() )
            err_folder = CUR_PATH + "/../errfile_bcs/"
            if 'md5' in file_info.keys() and 'file_body' in file_info.keys() and err != errcode.E_OK and err != errcode.E_FILE_IO:
                f = open(err_folder + file_info['md5'], 'wb')
                f.write(file_info['file_body'])
                f.close()

            logger_d.info("bcs put failed md5:%s, bucket:%s, body_len:%d" % (file_info["md5"], bucket,  len(file_info["file_body"])))
            file_info['file_exist_flag'] = 2
        else:
            file_info['file_exist_flag'] = 1
            logger_d.info("bcs set success md5:%s to bucket:%s, body_len:%d" % (file_info["md5"], bucket, len(file_info["file_body"])))
        return err

    @DecoLog()
    def _write_database(self, file_info, type):
        """Read the information from redis and write the file information to the database"""
        if self._send_basic_info(file_info, type) != errcode.E_OK:
            return errcode.E_WRITE_DB
        logger_d.info("send basic")

        if self._send_pe_info(file_info, type) != errcode.E_OK:
            return errcode.E_WRITE_DB
        logger_d.info("send pe")

        if self._send_path_info(file_info, type) != errcode.E_OK:
            return errcode.E_WRITE_DB
        logger_d.info("send path")
        
        self._send_url_info(file_info, type)

        return errcode.E_OK

    @DecoLog()
    def _parse_pe(self, file_info):
        try:
            p = pe_parser.ParsePEFile(file_info['file_body'], file_info['md5'])
            file_info['pe_info'] = p.get_peinfo()
            file_info['is_pe_broken'] = 0
            file_info['type_id'] = 1 #pe file
            return errcode.TYPE_PE
        except pefile.PEFormatError,e:
            if e.value != 'DOS Header magic not found.':
                file_info['type_id'] = 1 #no pe file
                file_info['is_pe_broken'] = 1
                logger_e.error("get pe %s from client %s at %s info failed: %s" % (file_info['md5'], file_info['guid'], file_info['file_path'], e.value))
                return errcode.TYPE_BADPE
            else:
                file_info['type_id'] = 2 #no pe file
                logger.debug("get nope %s from client %s at %s" % (file_info['md5'], file_info['guid'], file_info['file_path']))
                return errcode.TYPE_NOPE
        except:
            logger_e.error("get pe %s from client %s at %s info failed: %s" % (file_info['md5'], file_info['guid'], file_info['file_path'], traceback.format_exc()))
            file_info['type_id'] = 1 #no pe file
            file_info['is_pe_broken'] = 1
            return errcode.TYPE_BADPE

    @DecoLog()
    def _parse_file_type(self, file_info):
        file_data = file_info['file_body']
        file_name = file_info['file_real_path']
       
        zip_body = StringIO.StringIO(file_data)
        if zipfile.is_zipfile(zip_body):
            logger.debug("file:%s", file_info['file_real_path'])
            if nope_parser.ParseAPKFile(file_data) == errcode.E_OK:
                return errcode.TYPE_APK   
            if nope_parser.ParseJARFile(file_data) == errcode.E_OK:
                return errcode.TYPE_JAR
        else:
            if nope_parser.ParseCLASSFile(file_data) == errcode.E_OK:
                return errcode.TYPE_CLASS
            if nope_parser.ParseSWFFile(file_data) == errcode.E_OK:
                return errcode.TYPE_SWF
        return errcode.TYPE_OTHER
        
    @DecoLog()
    def _compute_half_md5(self, file_info):
        file_content = file_info['file_body']
        file_begin = file_content[0:1024*1024]
        file_end = file_content[-1024*1024:]
        size = struct.pack("i", file_info['file_size'])
        half_buf = file_begin + file_end + size
        file_info['half_md5'] = hashlib.md5(half_buf).hexdigest()
        logger_d.info("compute md5 :%s, half_md5 :%s" % (file_info['md5'], file_info['half_md5']))

    @DecoLog()
    def _check_md5(self, file_info):
        """unzip the file and ckeck the md5 string"""
        ##check file md5
        try:
            zz_md5 = hashlib.md5(file_info["block_file_body"]).hexdigest().lower()
            if zz_md5 == file_info['compress_md5'].lower():
                logger.debug("ZIP MD5 check sucessfully!")
            else:
                logger_e.error("zip md5 check failed! original md5 = %s new md5 = %s client %s file %s" % (file_info['compress_md5'].lower(), zz_md5, file_info['guid'], file_info['file_path']))
                return errcode.E_MD5_CHECK
            #unzip
            zip_body = StringIO.StringIO(file_info["block_file_body"])
            zp = zipfile.ZipFile(zip_body)
            real_file_path = zp.namelist()[0]
            logger.debug("real_flie_path = %s" % real_file_path)
            file_content = zp.read(real_file_path)
            
            #decryt
            if file_info['source_id'] == 4 and file_info['sub_source_id'] == 3:
                logger_d.info("decry md5:%s" % file_info['md5'])
                file_content = self._data_decrypt(file_content)

            c_f_md5 = hashlib.md5(file_content).hexdigest()
            zp.close()

            file_info["block_file_body"] = file_content
            file_info["file_real_path"] = real_file_path 
            
            if c_f_md5 == file_info['block_md5'].lower():
                logger.debug("MD5 check sucessfully!")
                return errcode.E_OK
            else:
                logger_e.error("md5 check failed! original md5 = %s new md5 = %s client %s file %s" % (file_info['block_md5'].lower(), c_f_md5, file_info['guid'], file_info['file_path']))
                return errcode.E_MD5_CHECK
        except:
            logger_e.error("Zip file Exception: %s guid is %s file_path is %s" % (traceback.format_exc(),file_info['guid'],file_info['file_path']))
            return errcode.E_FILE_IO
    
    @DecoLog()
    def _build_proto_info(self, q_item, file_info):
        """ build the dict from the q_item protobuf struct
            Please reference the related document in the svn"""
        logger.debug("request packet : %s" % q_item)

        #items from protobuf
        file_info["md5"] = q_item.md5
        file_info["block_md5"] = q_item.block_md5
        file_info["compress_md5"] = q_item.compress_md5
        file_info["file_attribute"] = q_item.file_attribute
        file_info["type_id"] = q_item.type_id
        file_info["file_sub_type"] = q_item.file_sub_type
        file_info["source_id"] = q_item.source_id
        file_info["sub_source_id"] = q_item.sub_source_id
        file_info["guid"] = q_item.guid
        file_info["index"] = q_item.index
        file_info["client_ip"] = q_item.client_ip
        file_info["local_ip"] = q_item.local_ip
        file_info["create_time"] = q_item.create_time
        file_info["access_time"] = q_item.access_time
        file_info["modify_time"] = q_item.modify_time
        file_info["os_version"] = q_item.os_version
        file_info["file_path"] = q_item.file_path
        if q_item.HasField("url"):
            file_info["url"] = q_item.url

        #for iterate 
        if q_item.file_path.find('Application Data\\Application Data') != -1:
            file_info["file_path"]=" "

        if hasattr(q_item, 'scan_source_id'):
            file_info['scan_source_id'] = q_item.scan_source_id
        else:
            file_info['scan_source_id'] = 2 # passed from the file_upload module

    @DecoLog()
    def _build_extra_info(self, file_info):
        """ build other info dicts from protobuf info dict"""

        file_info['crc32'] = binascii.crc32(file_info['file_body']) & 0xffffffff
        file_info['sha1'] = hashlib.sha1(file_info['file_body']).hexdigest()
        file_info['file_size'] = len(file_info['file_body'])
        file_info['insert_time'] = int(time.time())
        file_info['file_exist_flag'] = 0  #0 unknown 1 stored 2 not stored
        file_info['vdc_update'] = 0
        file_info['pe_update'] = 0
        file_info['filelist_update'] = 0
        file_info['comment'] = '' 
        file_info['info_version'] = 1

        #mongo db index
        file_info['_id'] = file_info['md5']
         

    @DecoLog()
    def _send_request(self, cmd_id, sub_cmd_id, file_info, type):
        #@type 1:normal pe 2:big pe 3:apk 4:url
        inner_header_buf = self._build_inner_header(cmd_id, sub_cmd_id)
        
        #build body
        udp_sock = None
        if cmd_id == const.IN_CMD_NOTICEDISPATCHER:
            body = notice_dispatcher_pb2.NoticeDispatcher()
            if type == 1:
                self.s = UDPSender(self.dp_server, self.dp_port)
            elif type == 2:
                self.s = UDPSender(self.bp_dp_server, self.bp_dp_port)
            elif type == 3:
                self.s = UDPSender(self.apk_dp_server, self.apk_dp_port)
            else:
                return errcode.E_OK
            #pe summary request packet
            if self.pesummary_server !="" and self.pesummary_port != 0:
                udp_sock = UDPSender(self.pesummary_server, self.pesummary_port)
            logger.debug("udpsend offline dispatcher md5:%s" % (file_info['md5']))

            body.md5 = file_info['md5']
            body.md5_type = const.MD5_TYPE_ALL
            body.file_size = file_info["file_size"]
            body.file_type = file_info["type_id"]
            
            #
            body.source_id = file_info["source_id"]
            body.sub_source_id = file_info["sub_source_id"]
            body.scan_source_id = file_info['scan_source_id'] 
            if file_info.has_key('file_subtype'):
                body.file_subtype = file_info['file_subtype']
            if file_info.has_key('type_id'):
                body.type_id = file_info['type_id']

            body_buf = body.SerializeToString()
            return self._build_file_info_request(self.s, inner_header_buf, body_buf)
        else:
            body = notice_dc_pb2.NoticeDC()
            logger.debug("udpsend data center md5:%s" % (file_info['md5']))

            body.md5 = file_info['md5']
            body.md5_type = const.MD5_TYPE_ALL
            body.file_size = file_info["file_size"]
            body.file_type = file_info["type_id"]
            #
            body.file_upload_time = int(time.time())
            if file_info.has_key('half_md5'):
                body.half_md5 = file_info['half_md5']

            body_buf = body.SerializeToString()
            if type == 1:
                self.s = UDPSender(self.dc_server, self.dc_port)
                return self._build_file_info_request(self.s, inner_header_buf, body_buf)
            elif type == 2:
                self.s = UDPSender(self.dc_server, self.dc_port)
                self._build_file_info_request(self.s, inner_header_buf, body_buf)

                self.s = UDPSender(self.bp_dc_server, self.bp_dc_port)
                return self._build_file_info_request(self.s, inner_header_buf, body_buf)
            elif type == 3:
                self.s = UDPSender(self.apk_dc_server, self.apk_dc_port)
                return self._build_file_info_request(self.s, inner_header_buf, body_buf)
            else:
                return errcode.E_OK


    @DecoLog()
    def _build_inner_header(self, cmd_id, sub_cmd_id):
        hd = inner_header_pb2.InnerHeader()
        hd.cmd = cmd_id
        hd.subcmd = sub_cmd_id
        hd.seq = 0
        hd.protoversion = 0

        for i in range(10):  #add 10 bytes context for test
            hd.context.append('8')

        inner_header_buf = hd.SerializeToString()

        return inner_header_buf

    @DecoLog()
    def _build_file_info_request(self, sock, inner_header_buf, body_buf):

        dw_header_len = len(inner_header_buf)
        dw_body_len = len(body_buf)

        dw_total_len = dw_header_len + dw_body_len + 6*2 + 4
        header_info = struct.pack("!IIH", dw_total_len, dw_header_len, const.TYPE_INNERHEADER)
        body_info = struct.pack("!IH", dw_body_len, const.TYPE_BODY)

        #TODO:use .join instead of '+'
        request_buf = header_info + inner_header_buf + body_info + body_buf

        # send the buffer
        ret = sock.send_udp_packets(request_buf, dw_total_len)
        return ret

    @DecoLog()
    def _send_url_info(self, file_info, type):
        #@type 1:normal pe 2:big pe 3:apk
        """Send the path info to the DBA server"""
        url = file_info.get('url', '')
        if len(url) == 0:
            return errcode.E_OK
        dba_sock = None
        if type == 1 or type == 2:
            dba_sock = UDPSender(self.dba_server, self.dba_port)
        elif type == 3:
            dba_sock = UDPSender(self.apk_dba_server, self.apk_dba_port)
        else:
            return errcode.E_OK        

        try:
            #don't send the path info for big search data
            if file_info['source_id'] >= 103:
                return errcode.E_OK

            dba_url = dba_url_info_pb2.DBAUrlInfo()
            
            dba_url._id = file_info['md5']
            dba_url.path = url
            dba_url.path_md5 = hashlib.md5(url).hexdigest()

            body_buf = dba_url.SerializeToString()

            logger.debug("url info: (path, %s);(path_md5, %s);" % 
                        (dba_url.path, dba_url.path_md5))
            #build inner header
            inner_header_buf = self._build_inner_header(const.IN_CMD_SENDURLINFO, const.IN_SUBCMD_IN)

            #build request and send
            logger.debug("send the packets url %s " % file_info['md5'])
            if dba_sock is not None:
                return self._build_file_info_request(dba_sock, inner_header_buf, body_buf)
            else:
                return errcode.E_FAIL
        except:
            logger_e.error("send url info failed: %s" % traceback.format_exc())
            return errcode.E_NET_IO


    @DecoLog()
    def _send_path_info(self, file_info, type):
        #@type 1:normal pe 2:big pe 3:apk
        """Send the path info to the DBA server"""
        dba_sock = None
        if type == 1 or type == 2:
            dba_sock = UDPSender(self.dba_server, self.dba_port)
        elif type == 3:
            dba_sock = UDPSender(self.apk_dba_server, self.apk_dba_port)
        else:
            dba_sock = UDPSender(self.url_dba_server, self.url_dba_port)

        try:
            #don't send the path info for big search data
            if file_info['source_id'] >= 103:
                return errcode.E_OK

            dba_path = dba_path_info_pb2.DBAPathInfo()
            
            full_path = file_info['file_path']
            if len(full_path) == 0:
                logger_e.error("The file %s full path is Null" % file_info['md5'])
                #return errcode.E_FAIL
                
                dba_path._id = file_info['md5']
                dba_path.file_path = ''#full_path
                dba_path.file_name = ''#full_path
                dba_path.path_md5 = ''
                dba_path.suffix = ''#full_path
            else:

                sep = full_path.rfind('\\')
                file_name = full_path[sep+1:]
                file_info['file_name'] = file_name

                dba_path._id = file_info['md5']
                dba_path.file_path = full_path
                dba_path.file_name = file_info['file_name']
                dba_path.path_md5 = hashlib.md5(full_path).hexdigest()
                dba_path.suffix = file_name.split('.')[-1] == file_name and '' or file_name.split('.')[-1]

            body_buf = dba_path.SerializeToString()

            logger.debug("Path info: (file_path, %s);(file_name ,%s);(path_md5, %s);(suffix, %s)" % 
                        (dba_path.file_path, dba_path.file_name, dba_path.path_md5, dba_path.suffix))
            #build inner header
            inner_header_buf = self._build_inner_header(const.IN_CMD_SENDPATHINFO, const.IN_SUBCMD_IN)

            #build request and send
            logger.debug("send the packets path %s " % file_info['md5'])
            if dba_sock is not None:
                return self._build_file_info_request(dba_sock, inner_header_buf, body_buf)
            else:
                return errcode.E_FAIL
        except:
            logger_e.error("send path info failed: %s" % traceback.format_exc())
            return errcode.E_NET_IO

    @DecoLog()
    def _send_basic_info(self, file_info, type):            
        #@type 1:normal pe 2:big pe 3:apk
        """Send the basic info the DBA server"""
        dba_sock = None
        if type == 1 or type == 2:
            dba_sock = UDPSender(self.dba_server, self.dba_port)
        elif type == 3:
            dba_sock = UDPSender(self.apk_dba_server, self.apk_dba_port)
        else:
            dba_sock = UDPSender(self.url_dba_server, self.url_dba_port)
            
        try:
            # build inner header
            inner_header_buf = self._build_inner_header(const.IN_CMD_SENDBASICINFO, const.IN_SUBCMD_IN)

            #build body
            dba_basic = dba_basic_info_pb2.DBABasicInfo()
            dba_basic._id = file_info['md5']

            for key in file_info.keys():
                if key != 'file_path' and hasattr(dba_basic, key): # file_path will be write by the dba_path_info packet
                    logger.debug("Basic info (%s, %r)" % (key, file_info[key]))
                    setattr(dba_basic, key, file_info[key])

            body_buf = dba_basic.SerializeToString()

            #build request and send
            logger.debug("send the packets basic %s " % file_info['md5'])
            if dba_sock is not None:
                return self._build_file_info_request(dba_sock, inner_header_buf, body_buf)
            else:
                return errcode.E_FAIL
        except:
            logger_e.error("send basic info failed: %s" % traceback.format_exc())
            return errcode.E_NET_IO
        return errcode.E_OK

    @DecoLog()
    def _send_pe_info(self, file_info, type):
        #@type 1:normal pe 2:big pe 3:apk
        dba_sock = None
        if type == 1 or type == 2:
            dba_sock = UDPSender(self.dba_server, self.dba_port)
        elif type == 3:
            dba_sock = UDPSender(self.apk_dba_server, self.apk_dba_port)
        else:
            dba_sock = UDPSender(self.url_dba_server, self.url_dba_port)

        if not file_info.has_key('pe_info') or file_info['pe_info'] == None:
            logger.debug("The pe_info is None for file %s" %  file_info['md5'])
            return errcode.E_OK
        
        pe_info = file_info['pe_info']
        
        try:
            if pe_info is None:
                logger_e.error("The pe_info is None for file %s" %  file_info['md5'])

            #build body
            dba_pe = dba_pe_info_pb2.DBAPeInfo()
            dba_pe._id = file_info['md5']

            for key in file_info['pe_info'].keys():
                if hasattr(dba_pe, key):
                    logger.debug("PE info (%s, %r)" % (key, pe_info[key]))
                    setattr(dba_pe, key, pe_info[key])

            body_buf = dba_pe.SerializeToString()

            #build inner header
            inner_header_buf = self._build_inner_header(const.IN_CMD_SENDPEINFO, const.IN_SUBCMD_IN)

            #build request and send
            logger.debug("send the packets pe %s " % file_info['md5'])
            if dba_sock is not None:
                return self._build_file_info_request(dba_sock, inner_header_buf, body_buf)
            else:
                return errcode.E_FAIL
        except:
            logger_e.error("send pe info failed: %s" % traceback.format_exc())
            return errcode.E_NET_IO
        return errcode.E_OK
    
    @DecoLog()
    def _recv_parse_request(self, _sock):
        '''
            packet = dwTotalLen + dwInnerHeaderLen + wType + InnerHeader + dwBodyTotalLen + wType + dwInfoLen + Info + dwFileLen + File 
        '''
        try:
            with Timeout(self.recv_timeout, False):
                #recv total packet
                h = _sock.recv(4)
                total_len = struct.unpack("!I", h)[0]
                
                left = total_len - 4
                h = ""
                while left > 0:
                    tmp = _sock.recv(left)
                    if len(tmp) == 0:
                        break
                    h += tmp
                    left -= len(tmp)
               
                 
                cur_len = 0
                inner_header_len, w_type = struct.unpack("!IH", h[cur_len : cur_len + 6])
                cur_len += 6
                
                inner_beader_buf = h[cur_len:cur_len+inner_header_len]
                cur_len += inner_header_len
                
                tmp_len, tmp_type, body_info_len = struct.unpack("!IHI", h[cur_len : cur_len + 10])
                cur_len += 10
                
                body_info = h[cur_len : cur_len + body_info_len]
                cur_len += body_info_len
                
                file_len = struct.unpack("!I", h[cur_len : cur_len + 4])[0]
                cur_len += 4 
                
                file = h[cur_len : cur_len + file_len]
                return body_info, file
        
            return None, None
        except :
            logger_e.error("recv&parse packet failed: %s" % traceback.format_exc())
            return None,None
    
    @DecoLog()
    def _check_request(self, info_buf, file_info):
        """Check the md5 for the file"""
        try:
            #parse info protobuf struct
            q_item = file_upload_pb2.FileInfo()
            q_item.ParseFromString(info_buf)
            
            #build basic file info
            self._build_proto_info(q_item, file_info)
            
            # md5 or pe is not matched, will return directly
            ret = self._check_md5(file_info)
            if ret != errcode.E_OK:
                return ret

            return errcode.E_OK
        except:
            logger_e.error("check exception: %s" % traceback.format_exc())
            return errcode.E_PARSE_PACKET
    
    @DecoLog()
    def _report_dailylog(self, start_time, file_info, err):
        #record log
        end_time = time.time()
        delta_time = int((end_time - start_time)*1000000)
        if 'md5' in file_info.keys() and 'source_id' in file_info.keys() and 'guid' in file_info.keys():
            if err == errcode.E_OK:
                logger_d.info("process succ | md5:%s | code:%d | source_id:%d |time :%d| guid:%s | typeid:%d | filesubid:%d | sub_source_id:%d" % (file_info['md5'], err, file_info['source_id'], delta_time, file_info['guid'], file_info['type_id'], file_info['file_subtype'], file_info['sub_source_id']))
                AgentModule.AgentRepSum(Report.QUERY_SUCC, 1)
            else:
                logger_d.info("process fail | md5:%s | code:%d | source_id:%d |time :%d| guid:%s | sub_source_id:%d" % (file_info['md5'], err, file_info['source_id'], delta_time, file_info['guid'], file_info['sub_source_id']))
        else:
            logger_d.info("process fail | parse packet failed")
        
        #report 
        if file_info.has_key("source_id"):
            if file_info['source_id'] == 4:
                #AgentModule.AgentRepSum(Report.X_QUERY_CNT, 1)
                if err == errcode.E_OK:
                    AgentModule.AgentRepSum(Report.X_QUERY_SUCC_CNT, 1)
            elif file_info['source_id'] == 5:
                #AgentModule.AgentRepSum(Report.AURORA_QUERY_CNT, 1)
                if err == errcode.E_OK:
                    AgentModule.AgentRepSum(Report.AURORA_QUERY_SUCC_CNT, 1)
            elif file_info['source_id'] == 103:
                #AgentModule.AgentRepSum(Report.OFFLINE_QUERY_CNT, 1)
                if err == errcode.E_OK:
                    AgentModule.AgentRepSum(Report.OFFLINE_QUERY_SUCC_CNT, 1)
   
        #keep failed file
        #err_folder = CUR_PATH + "/../errfile/"
        #if 'md5' in file_info.keys() and 'file_body' in file_info.keys() and err != errcode.E_OK and err != errcode.E_FILE_IO:
        #    f = open(err_folder + file_info['md5'], 'wb')
        #    f.write(file_info['file_body'])
        #    f.close()
 
    @DecoLog()
    def __call__(self, _socket, address):
        start_time = time.time()
        file_info = {}
        try:
            #logger_d.info("process info start")
            AgentModule.AgentRepSum(Report.QUERY_CNT, 1) # all file process request
            
            #recv and parse request
            info_buf, file_info["block_file_body"] = self._recv_parse_request(_socket)
            if file == None:
                AgentModule.AgentRepSum(Report.E_REQUEST_PACKET_FAIL,1)
                self._report_dailylog(start_time, file_info, errcode.E_NET_IO)
                return 
    
            #check the request
            ret = self._check_request(info_buf, file_info)
            if ret != errcode.E_OK and ret != errcode.E_PE_BROKEN:
                if ret == errcode.E_PARSE_PACKET:
                    AgentModule.AgentRepSum(Report.E_PARSER_REQUEST_FAIL, 1)
                elif ret == errcode.E_MD5_CHECK:
                    AgentModule.AgentRepSum(Report.E_MD5_CHECK_FAIL, 1)
                elif ret == errcode.E_FILE_IO:
                    AgentModule.AgentRepSum(Report.E_ZIP_FAIL, 1)
                elif ret == errcode.E_PE_BROKEN:
                    AgentModule.AgentRepSum(Report.E_BAD_PE, 1)
                else:
                    AgentModule.AgentRepSum(Report.E_OTHER_FAIL, 1)
                logger_e.error("ret:%d" % ret)
                self._report_dailylog(start_time, file_info, ret)
                return 
            #if ret == errcode.E_PE_BROKEN:
            #    AgentModule.AgentRepSum(Report.E_BAD_PE, 1)
            md5_name=file_info['md5']
            key_index=self._get_redis_num(md5_name)
            conn =self.redis_conn_list[key_index] 
            merge_hash = "merge_%s" % md5_name 
            #print merge_hash
            #print file_info["index"]
            local_merge=conn.hgetall(merge_hash)
            if(len(local_merge)==0):
                logger_d.info("merge hash %s is not exist and creat for index %s" % (md5_name,file_info['index']))
                return
            if local_merge[file_info['index']]=='1':
                AgentModule.AgentRepSum(Report.RE_UPLOAD, 1)
                return
            if not self._write_file_tolocal(file_info):
                AgentModule.AgentRepSum(Report.WRITE_LOCAL_ERROR, 1)
                return
            local_merge[file_info['index']]='1'
            #print local_merge
            if '0' in local_merge.values():
                conn.hset(merge_hash,file_info['index'],1)
                AgentModule.AgentRepSum(Report.BLOCK_SUCC, 1)
                return
            else:
                if(self._merge_file(md5_name,len(local_merge)-1,file_info)):
                    conn.hset(merge_hash,file_info['index'],1)
                    AgentModule.AgentRepSum(Report.MERGE_SUCC, 1)
                    logger_d.info("worker get merge file %s" % md5_name)
                else:
                    print local_merge
                    #for key in local_merge.keys():
                    #    if key=="time":
                    #        continue
                    #    local_merge[key]=0
                    #conn.hmset(merge_hash,local_merge)
                    return 
            try:
                # build packet extra info
                self._build_extra_info(file_info)

                # check file type and parse PE struct
                file_info['file_subtype'] = 0
                ret = self._parse_pe(file_info)

                if file_info.has_key('pe_info'):
                    if file_info['pe_info'].has_key('file_subtype'):
                        file_info['file_subtype'] = file_info['pe_info']['file_subtype']              
                if ret == errcode.TYPE_NOPE:
                    file_type = self._parse_file_type(file_info)
                    file_info['pe_info'] = {}
                    file_info['pe_info']['file_subtype'] = file_type
                    file_info['file_subtype'] = file_type
                    logger.debug("set file_sbutype:%s %d" % (file_info["md5"], file_info['pe_info']['file_subtype']))
                elif ret == errcode.TYPE_BADPE:
                    AgentModule.AgentRepSum(Report.E_BAD_PE, 1)
            except:
                logger_e.error("check exception: %s" % traceback.format_exc())
                return    
            #write mola
            #for i in range(self.mola_retry):
            #    ret = self._write_file_to_mola(file_info)
            #    if ret == errcode.E_OK:
            #        break;
            #    else:
            #        logger.debug("mola write retry file_md5:%s, try count:%d" % (file_info['md5'], i))
            #if ret != errcode.E_OK:
            #    AgentModule.AgentRepSum(Report.E_WRITE_MOLA, 1)
            #    self._report_dailylog(start_time, file_info, ret)
            #    return
            
            logger_d.info("process info write bcs")
            #write to bcs
            if self._write_file_to_bcs(file_info) != errcode.E_BCS_OK:
                AgentModule.AgentRepSum(Report.E_WRITE_BCS_FAIL, 1)
            self._write_file_to_bos(file_info)

            #deal_tpype 1:small pe 2:big pe 3:apk 4:url
            #compute half md5
            deal_type = None
            if file_info.get('file_subtype', 0) == errcode.TYPE_APK:
                deal_type = 3
                #AgentModule.AgentRepSum(Report.APK_CNT, 1)
                logger_d.info("process info start db apk")
            elif file_info['file_size'] <= 16*1024*1024:
                deal_type = 1
                logger_d.info("process info start db small pe")
            else:
                self._compute_half_md5(file_info)
                deal_type = 2
                #AgentModule.AgentRepSum(Report.BIGPE_CNT, 1)
                logger_d.info("process info start db big pe")

            if file_info.get("source_id", 0) == 11 and file_info.get("sub_source_id", 0) == 1:
                logger_d.info("process info start db url")
                deal_type = 4

            if deal_type is not None:
                ret = self._write_database(file_info, deal_type)
                if ret != errcode.E_OK:
                    AgentModule.AgentRepSum(Report.E_WRITE_DB_FAIL, 1)
                    self._report_dailylog(start_time, file_info, ret)
                    return

                logger_d.info("process info write dispatch") 
                ret = self._send_request(const.IN_CMD_NOTICEDISPATCHER, const.IN_SUBCMD_IN, file_info, deal_type)
                if ret != errcode.E_OK:
                    AgentModule.AgentRepSum(Report.E_OTHER_FAIL, 1)
                    self._report_dailylog(start_time, file_info, errcode.E_SEND_DISPATCH)
                    return

                logger_d.info("process info datacenter")
                #send request to dc
                ret = self._send_request(const.IN_CMD_NOTICEDC,const.IN_SUBCMD_IN, file_info, deal_type)
                if ret != errcode.E_OK:
                    AgentModule.AgentRepSum(Report.E_OTHER_FAIL, 1)
                    self._report_dailylog(start_time, file_info, errcode.E_SEND_DC)
                    return
                    
            rmfile=os.path.join(DSTPATH,file_info["md5"])
            if os.path.exists(rmfile):
                os.remove(rmfile)        
            self._del_file(md5_name,len(local_merge)-1,file_info)
            #process success
            self._report_dailylog(start_time, file_info, errcode.E_OK)
            logger_d.info("process info end")
            #subject="file upload suc %s" % file_info["md5"]
            #content=subject
            #sender="wangchaojie@baidu.com"
            #receives = ["gaohongwei@baidu.com","v_zhangxin01@baidu.com", "huangmengmeng01@baidu.com", "wangchaojie@baidu.com"]
            #mail.send_mail("proxy-in.baidu.com", sender, receives, subject, content)
                
        except:
            AgentModule.AgentRepSum(Report.E_OTHER_FAIL, 1)
            self._report_dailylog(start_time, file_info, errcode.E_FAIL)
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
    #    print "new process %d" % os.getpid()
        put_pid_file()
        #server.start_accepting()
        server.serve_forever()
        #server._stopped_event.wait()

   
    #get configuration
    server_ip = config.get_string("Server", "processor_ip", "0.0.0.0")
    server_port = config.get_int("Server", "processor_server_port", 8003)
    pool_size = config.get_int("Server", "processor_pool_size", 4)
   
    
    #init mola configuration
    #fp = open(CUR_PATH + '/../conf/mola_ip.ini', 'r')
    #lines = fp.readlines()
    #for line in lines:
    #    line = line.strip()
    #    mola_addAddress(line, 9999)

    bcs = bcs_serve.bcs_create(bcs_serve.HOST, bcs_serve.AK, bcs_serve.SK)
    file_process = FileProcessor(bcs)
   
    pool = pool.Pool(pool_size)
    server = StreamServer((server_ip, server_port), file_process, spawn = pool, backlog=100000)
    server.max_accpet = 10000
    server.start()
    process_count = config.get_int("Server", "processor")

    for i in range(process_count - 1):
        Process(target=serve_forever, args=(server,)).start()

    serve_forever(server)

