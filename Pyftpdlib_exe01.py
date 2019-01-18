#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################
# 程序功能：ftp服务器                                             #
# 运行环境：Centos7.x 64位                                       #
# 依赖库：pyftpdlib==1.5.4、pyOpenSSL==0.13.1、pysendfile==2.0.1 #
###############################################################

"""加载所需库"""
import logging
import sys
from hashlib import md5
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

"""设置输出日志路径、格式"""
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(process)d %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='/var/log/Pyftpd.log',
    filemode='a',
)


"""设置密码md5加密类"""
class DummyMD5Authorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        if sys.version_info >= (3, 0):
            password = md5(password.encode('latin1'))
        hash = md5(password).hexdigest()
        try:
            if self.user_table[username]['pwd'] != hash:
                raise KeyError
        except KeyError:
            raise AuthenticationFailed

"""FTP主函数代码"""
def main():
    authorizer = DummyMD5Authorizer()
    passwd = md5('123456').hexdigest()
    authorizer.add_user('user', passwd, '.', perm='elradfmwMT')
    #authorizer.add_anonymous(os.getcwd())
    authorizer.add_anonymous('/opt/')

    handler = FTPHandler
    handler.authorizer = authorizer

    handler.banner = "pyftpdlib based ftpd ready."

    address = ('', 2121)
    server = FTPServer(address, handler)
    server.max_cons = 256
    server.max_cons_per_ip = 5
    server.serve_forever()
if __name__ == '__main__':
    main()

