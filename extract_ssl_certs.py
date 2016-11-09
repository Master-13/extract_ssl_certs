#coding=utf-8
#version:20161026
import dpkt
import struct, socket, sys, os, argparse, logging, md5

parser = argparse.ArgumentParser(description='Extract SSL certs')
parser.add_argument("-f", "--file", action='store', help="Extract SSL certificates from a single file.", default = None)
parser.add_argument("-d", "--dir", action='store', help="Extract SSL certificates from a directory containing cap files.", default = None)
parser.add_argument("-e", "--exclude", action='store', help="Filename containing skip ip list, ip list in this file will be skip when extracting.", default=None)
#parser.add_argument("-h", "--help")
parser.add_argument("-l", "--log", action='store', help="Filename to save console log", default = None)

args = parser.parse_args()

def showUsage():
    print 'extract_ssl_certs.py [-f 文件名|-d 目录] [-e 排除IP列表文件] [-l log]'

if args.file is None and args.dir is None or args.file is not None and args.dir is not None:
    print "Either -f or -d is required, but can't be both there."
    showUsage()
    exit(-1)

####################################
# Setting log
log = logging.getLogger('extractor')
log_format = logging.Formatter("%(asctime)s %(lineno)s %(levelname)-07s %(message)s")
stdHandler = logging.StreamHandler(sys.stdout)
stdHandler.setFormatter(log_format)
log.addHandler(stdHandler)
log.setLevel(logging.DEBUG)
if args.log != None:
    fh = logging.FileHandler(args.log)
    fh.setFormatter(log_format)
    log.addHandler(fh)


#####################################
# Global vars
doneList=[]
certcount=0
try:
    os.mkdir('certs')
except:
    pass

if args.exclude != None:
    try:
        with open(args.exclude,'rb') as f:
            lines=f.readlines()
        for line in lines:
            doneList.append(line.strip(' \r\n'))
    except:
        pass

def extract_file(filepath):
    if not filepath.endswith('cap'):
        return
    
    global certcount
    log.debug('Extract: %s' % (filepath))
    tcp_piece={}
    f = open(filepath,'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        log.error("Error reading cap: %s", filepath)
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
                if srcip in doneList:
                    continue
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
        #md5_dstip_dstport=md5.md5(t4[1]+str(t4[3])).hexdigest()
        if srcip in doneList:
            continue
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
            #如果不是Handshake类型
            if sslcombined[curpos]!='\x16':
                break
            handshake_len=struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
            curpos+=5
            cur_handshakelen=0
            while(cur_handshakelen<handshake_len and curpos+4<totallen):
                this_handshake_len=struct.unpack('!I', '\x00'+sslcombined[curpos+1:curpos+4])[0]
                if sslcombined[curpos]=='\x0b': #如果这一段是证书
                    certlen=struct.unpack('!I', '\x00'+sslcombined[curpos+4:curpos+7])[0]
                    if certlen>totallen:    #证书的长度超过了数据包的长度，通常是数据包数据丢失导致的
                        break                    
                    curpos+=7
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
                        log.info(filename)
                        sub_cert_count+=1         
                    certcount+=sub_cert_count-1
                else:
                    curpos+=this_handshake_len+4  #不是证书直接跳过
                cur_handshakelen+=this_handshake_len+4
            
            if cur_handshakelen>=handshake_len:
                continue
                

if args.dir!=None:
    for root, parent, files in os.walk(args.dir):
        for f in files:
            extract_file(root+os.sep+f)
            
elif args.file!=None:
    extract_file(args.file)

log.info('Extract %d cer files.' % certcount)
