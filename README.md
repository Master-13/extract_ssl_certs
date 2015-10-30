# exctract\_ssl_certs.py
从已有的pcap或cap文件中，提取HTTPS握手阶段产生的证书文件。
# 例子
D:\Python\提取证书>extract_ssl_certs.py -f d:\test\123.pcap  
2015-10-30 15:56:20,644 52 DEBUG   Extract: d:\test\123.pcap  
2015-10-30 15:56:21,084 120 INFO    192.243.112.130.crt  
2015-10-30 15:56:21,085 120 INFO    140.207.232.110.crt  
2015-10-30 15:56:21,086 120 INFO    61.135.169.121.crt  
2015-10-30 15:56:21,088 120 INFO    112.65.203.33.crt  
2015-10-30 15:56:21,088 120 INFO    110.76.18.156.crt  
2015-10-30 15:56:21,089 120 INFO    61.135.169.125.crt  
2015-10-30 15:56:21,091 120 INFO    140.207.232.109.crt  
2015-10-30 15:56:21,107 120 INFO    111.206.76.32.crt  
2015-10-30 15:56:21,109 120 INFO    203.208.40.158.crt  
2015-10-30 15:56:21,112 135 INFO    Extract 9 crt files.  
# 运行环境
- Python 2.7.X
- dpkt (python网络包解析，[了解更多](http://dpkt.readthedocs.org/en/latest/))

# 命令行参数
- `-f,--file`,与`-d`二选一，指定一个文件名，从该文件中提取ssl证书
- `-d,--dir`,与`-f`二选一，指定一个目录，从该目录及其子目录中的所有文件中，提取ssl证书
- `-e,--exclude`,可选,指定一个包含IP列表的文件，所有在此文件中的IP地址，将在提取过程中被跳过，用户可能希望跳过以获证书，或用来加速程序运行。

# extract\_ssl_certs.py
Extract ssl certificates from cap file
# Example
D:\Python\extract>extract_ssl_certs.py -f d:\test\123.pcap  
2015-10-30 15:56:20,644 52 DEBUG   Extract: d:\test\123.pcap  
2015-10-30 15:56:21,084 120 INFO    192.243.112.130.crt  
2015-10-30 15:56:21,085 120 INFO    140.207.232.110.crt  
2015-10-30 15:56:21,086 120 INFO    61.135.169.121.crt  
2015-10-30 15:56:21,088 120 INFO    112.65.203.33.crt  
2015-10-30 15:56:21,088 120 INFO    110.76.18.156.crt  
2015-10-30 15:56:21,089 120 INFO    61.135.169.125.crt  
2015-10-30 15:56:21,091 120 INFO    140.207.232.109.crt  
2015-10-30 15:56:21,107 120 INFO    111.206.76.32.crt  
2015-10-30 15:56:21,109 120 INFO    203.208.40.158.crt  
2015-10-30 15:56:21,112 135 INFO    Extract 9 crt files. 
# Runtime Env
- Python 2.7.X
- dpkt

# Args
- `-f,--file` Specifies a filename, from where this program extract ssl certificates.
- `-d,--dir` Specifies a directory of a folder, from where, besides its sub folder, program extract ssl certificates.
- `-e,--exclude`. Optional. Specifies a filename containing an ip list. Ips in this list will be skipped when extracting.
