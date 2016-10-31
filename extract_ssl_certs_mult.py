#coding=utf-8
#version:20161026
import dpkt
import struct, socket, sys, os, argparse, md5

import multiprocessing

#####################################
# Global vars

def showUsage():
    print 'extract_ssl_certs.py [-f 文件名|-d 目录]'

def extract_file(filepath):
    if not filepath.endswith('cap'):
        return

    print 'Extract: %s' % (filepath)
    tcp_piece={}
    f = open(filepath,'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print "Error reading cap: %s"%filepath
        return

    count=0
    try:
        for ts, buf in pcap:
            count+=1
            try:
                upperdata=dpkt.ethernet.Ethernet(buf).data
                while upperdata.__class__ not in [dpkt.ip.IP, str]:   #循环去找IP层，这主要是解决一些网络有pppoe和ppp层的缘故
                    upperdata=upperdata.data
                if upperdata.__class__==dpkt.ip.IP:
                    #if upperdata.sport!=443: continue
                    ippack=upperdata
                    tcppack=ippack.data
                    ssldata=tcppack.data
                else:   #IP层未找到
                    continue
                if not ssldata: continue    #如果是空就扔掉了，包括那个同一个SEQ对应的ACK的包
                srcip=socket.inet_ntoa(ippack.src)
                #定义了一个四元组（源IP，目的IP，源端口，目的端口）
                tuple4=(srcip, socket.inet_ntoa(ippack.dst), tcppack.sport, tcppack.dport)
                seq=tcppack.seq
                if not tcp_piece.has_key(tuple4):
                    tcp_piece[tuple4]={}
                tcp_piece[tuple4][seq]=ssldata
            except Exception,e:
                pass
    except Exception,e:
        print e.message
    f.close()
    
    #A->B和B->A是按两个流统计的，所以遍历一边源，就可以遍历到所有情况。
    for t4,dic in tcp_piece.iteritems():    #根据4元组进行组流
        srcip=t4[0]
        sport=t4[2]
        seq=min(dic.keys())
        sslcombined=dic[seq]
        piecelen=len(dic[seq])
        while(dic.has_key(seq+piecelen)):
            seq=seq+piecelen
            sslcombined+=dic[seq]
            piecelen=len(dic[seq])
        totallen=len(sslcombined)
        
        #do something
        curpos=0        
        while(curpos<totallen):
            #如果特别小，直接跳过
            if totallen-curpos<12: break
            #如果不是传递证书的包，跳过
            if sslcombined[curpos]!='\x16' or sslcombined[curpos+5]!='\x0b':
                curpos+=5+struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                continue
            #取得总长度
            certlen=struct.unpack('!I', '\x00'+sslcombined[curpos+9:curpos+12])[0]
            if certlen>totallen:    #证书的长度超过了数据包的长度，通常是数据包数据丢失导致的
                break
            if certlen>50000:
                print 'Very big cert.'
                curpos+=5+struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                continue
            
            curpos+=12
            sub_cert_len=0  #所有子证书的总大小            
            sub_cert_count=1    #子证书编号，编号形成证书链，越靠下越小
            while(sub_cert_len<certlen):
                this_sub_len=struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]   #当前子证书大小
                curpos+=3
                this_sub_cert=sslcombined[curpos:curpos+this_sub_len]
                sub_cert_len+=this_sub_len+3    #+3是“证书长度”，3个字节
                curpos+=this_sub_len
                md5cert=md5.md5(this_sub_cert).hexdigest()
                filename='%s_%d_%d_%s.cer' % (srcip, sport, sub_cert_count, md5cert)
                with open('certs\\%s' % filename, 'wb') as f:
                    f.write(this_sub_cert)
                print filename
                sub_cert_count+=1         
            break

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Extract SSL certs')
    parser.add_argument("-f", "--file", action='store', help="Extract SSL certificates from a single file.", default = None)
    parser.add_argument("-d", "--dir", action='store', help="Extract SSL certificates from a directory containing cap files.", default = None)
    parser.add_argument("-e", "--exclude", action='store', help="Filename containing skip ip list, ip list in this file will be skip when extracting.", default=None)
    
    args = parser.parse_args()
    if args.file is None and args.dir is None or args.file is not None and args.dir is not None:
        print "Either -f or -d is required, but can't be both there."
        showUsage()
        exit(-1)
    
    try:
        os.mkdir('certs')
    except:
        pass
    
    if args.dir!=None:
        cpu_count=multiprocessing.cpu_count()-2
        if cpu_count<0:
            cpu_count=1
        p=multiprocessing.Pool(cpu_count)
        for root, parent, files in os.walk(args.dir):
            if not files==[]:
                p.map(extract_file, map(lambda x:root+os.sep+x, files))
        
    elif args.file!=None:
        extract_file(args.file)
    