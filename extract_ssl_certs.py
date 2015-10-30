#coding=utf-8
import dpkt
import struct, socket, sys, os, argparse, logging

parser = argparse.ArgumentParser(description='Extract SSL certs')
parser.add_argument("-f", "--file", action='store', help="Extract SSL certificates from a single file.", default = None)
parser.add_argument("-d", "--dir", action='store', help="Extract SSL certificates from a directory containing cap files.", default = None)
parser.add_argument("-e", "--exclude", action='store', help="Filename containing skip ip list, ip list in this file will be skip when extracting.", default=None)
#parser.add_argument("-h", "--help")
parser.add_argument("-l", "--log", action='store', help="Filename to save console log", default = None)

args = parser.parse_args()

def showUsage():
    print 'extract_ssl_certs.py [-f filename|-d dirname] [-e exclude_ip_list] [-l log]'

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

if args.exclude != None:
    try:
        with open(args.exclude,'rb') as f:
            lines=f.readlines()
        for line in lines:
            doneList.append(line.strip(' \r\n'))
    except:
        pass

def extract_file(filepath):
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
                while upperdata.__class__ not in [dpkt.ip.IP, str]:   #循环去找IP层，这主要是解决一些网络有pppoe和ppp曾的缘故
                    upperdata=upperdata.data
                if upperdata.__class__==dpkt.ip.IP:
                    #if upperdata.sport!=443: continue
                    ippack=upperdata
                    tcppack=ippack.data
                    ssldata=tcppack.data
                else:   #IP层未找到
                    continue
                if not ssldata: continue
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

    for t4,dic in tcp_piece.iteritems():    #根据4元组进行组流
        srcip=t4[0]
        if srcip in doneList:
            continue
        seq=min(dic.keys())
        sslcombined=dic[seq]
        piecelen=len(dic[seq])
        while(dic.has_key(seq+piecelen)):
            seq=seq+piecelen
            sslcombined+=dic[seq]
            piecelen=len(dic[seq])

        curpos=0
        totallen=len(sslcombined)
        while(curpos<totallen):
            if totallen-curpos<12: break
            if sslcombined[curpos]!='\x16' or sslcombined[curpos+5]!='\x0b':
                curpos+=5+struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                continue
            certlen=struct.unpack('!I', '\x00'+sslcombined[curpos+9:curpos+12])[0]
            if certlen>totallen:    #证书的长度超过了数据包的长度，通常是数据包数据丢失导致的
                break
            if certlen>50000:
                log.warn('Very big cert.')
                curpos+=5+struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                continue
            cert=sslcombined[curpos+12:curpos+12+certlen]
            with open('%s.crt' % (srcip), 'wb') as f:
                f.write(cert[3:])
            log.info('%s.crt'%srcip)
            doneList.append(srcip)
            certcount+=1
            break
    f.close()

if args.dir!=None:
    for root, parent, files in os.walk(args.dir):
        for fn in files:
            if fn.endswith('cap'):
                extract_file(root+os.sep+fn)

elif args.file!=None:
    extract_file(args.file)

log.info('Extract %d crt files.' % certcount)
