#!/usr/bin/env python
#encoding:utf-8

#monkey patch
from gevent import monkey
monkey.patch_all(dns=False)
import redis
import time
from multiprocessing import Process
import os
import gevent
def dict_slice(mydict):
    retdict={}
    for k,v in mydict.items():
        if k=='time':
            continue
        retdict[k]=v
    return retdict
def update_search(conn,merge_conn):
    c_time = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))
    s_set=conn.smembers("search_set")
    #print s_set
    for m_md5 in s_set:
        search_hash = "search_%s" % m_md5
        merge_hash  = "merge_%s" % m_md5
        dict_m={}
        local_m={}
        dict_m=merge_conn.hgetall(merge_hash)
        local_m=dict_slice(dict_m)
        if(len(dict_m)==0):
            len_s=conn.hlen(search_hash)
            if(len_s!=0):
               list1=range(len_s)
               list2=[0]*len_s
               hash_m=dict(zip(list1,list2))
               merge_hash_m=hash_m
               merge_hash_m['time']='2'
               merge_conn.hmset(merge_hash,merge_hash_m)
               conn.hmset(search_hash,hash_m)
               print "crete merge_hash ",merge_hash_m 
        else:
            sync_time=int(dict_m['time'])
            if(sync_time==1442):
                print c_time,m_md5,"longer cannot erase"
                #merge_conn.delete(merge_hash)
            else:
                sync_time+=10
                dict_m['time']=str(sync_time)
                merge_conn.hmset(merge_hash,dict_m)
            conn.hmset(search_hash,local_m)
        #conn.srem("search_set",m_md5)
        print c_time,m_md5,dict_m


if __name__ == "__main__":
    redis_ip_list = ["10.52.175.35","10.212.118.25"]
    redis_port_list = [33333]*2
    merge_redis_ip="10.58.186.53"
    merge_redis_port=33333
    redis_conn_list = []
    for i in range(len(redis_ip_list)):
        #print redis_ip,redis_port
        redis_conn = redis.StrictRedis(host=redis_ip_list[i],port=redis_port_list[i], db=0)
        redis_conn_list.append(redis_conn)
    merge_conn = redis.StrictRedis(host=merge_redis_ip,port=merge_redis_port, db=0)
    threads = [gevent.spawn(update_search,conn,merge_conn) for conn in redis_conn_list]
    gevent.joinall(threads)

