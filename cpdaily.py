#coding=utf-8
import json
import execjs
import requests
from bs4 import BeautifulSoup as bs
import os
import base64
import hashlib
import pyaes
from pyDes import des, CBC, PAD_PKCS5

ua = 'Mozilla/5.0 (Linux; Android 11; M2102J2SC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36'

def getLogin(username,password):
    url="https://auth.sziit.edu.cn/authserver/login?service=https://sziit.campusphere.net/iap/loginSuccess"
    global session
    session=requests.session()
    g_response=session.get(url)
    soup = bs(g_response.text, 'html.parser')
    dt=soup.find_all('input',type="hidden")
    d=[]
    for x in dt:
        d.append(x.get('value'))

    pd = execjs.compile(open(r"encrypt.js").read()).call('encryptAES',password,d[5])

    data={
        "username":username,
        "password":pd,
        "captchaResponse":"",
        "lt":d[0],
        "dllt":d[1],
        "execution":d[2],
        "_eventId":d[3],
        "rmShown":d[4]
    }

    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'User-Agent': ua
               }
    session.post(url,data=data,headers=headers)


def getInfos():
    url = "https://sziit.campusphere.net/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay"
    response = session.post(url, headers={'Content-Type': 'application/json;charset=UTF-8','User-Agent': ua}, data="{}")
    d = json.loads(response.text)
    global signInstanceWid
    global signWid
    signInstanceWid=d["datas"]["unSignedTasks"][0]["signInstanceWid"]
    signWid=d["datas"]["unSignedTasks"][0]["signWid"]



def getForm(signInstanceWid,signWid):
    url = "https://sziit.campusphere.net/wec-counselor-sign-apps/stu/sign/detailSignInstance"
    payload = "\"signInstanceWid\": \"{a}\",\"signWid\": \"{b}\"".format(a=signInstanceWid,b=signWid)
    payload="{"+payload+"}"

    response = session.post(url, headers={'Content-Type': 'application/json;charset=UTF-8','User-Agent': ua}, data=payload)
    d = json.loads(response.text)
    global awid
    global bwid
    awid=d["datas"]["extraField"][0]["extraFieldItems"][1]["wid"]
    bwid=d["datas"]["extraField"][1]["extraFieldItems"][1]["wid"]

def AESEncrypt(s,key='ytUQ7l2ZZu8mLvJZ'):
    iv = b'\x01\x02\x03\x04\x05\x06\x07\x08\t\x01\x02\x03\x04\x05\x06\x07'
    Encrypter=pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key.encode('utf-8'),iv))
    Encrypted=Encrypter.feed(s)
    Encrypted+=Encrypter.feed()
    return base64.b64encode(Encrypted).decode()
def getSign(s):
    signStr=""
    for i in s:
        if signStr:
            signStr+="&"
        signStr+="{}={}".format(i,s[i])
    signStr+="&{}".format('ytUQ7l2ZZu8mLvJZ')
    return signStr
def DESEncrypt(s,Key="b3L26XNL"):
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    k = des(Key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    encrypt_str = k.encrypt(s)
    return base64.b64encode(encrypt_str).decode()

def submitForm(signInstanceWid,awid,bwid,username,deviceId):
    url = "https://sziit.campusphere.net/wec-counselor-sign-apps/stu/sign/submitSign"
    extension = {
            "systemName": "android",
            "systemVersion": "11",
            "model": "MI11",
            "deviceId": deviceId,
            "appVersion": "9.0.12",
            "lon": 114.222802,
            "lat": 22.69165,
            "userId": username,
    }
    extensionStr = DESEncrypt(json.dumps(extension))
    bodystr =AESEncrypt(str(bodyString))
    print(bodystr)
    print(extensionStr)
    header= {
    'Content-Type': 'application/json;charset=UTF-8',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 11; M2102J2SC Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/90.0.4430.210 Mobile Safari/537.36 cpdaily/9.0.12 wisedu/9.0.12',
    'Cpdaily-Extension':extensionStr
    }
    bodyString={"longitude":114.222802,"latitude":22.69165,"isMalposition":0,"abnormalReason":"","signPhotoUrl":"","isNeedExtra":1,"position":"\xe5\xb9\xbf\xe4\xb8\x9c\xe7\x9c\x81\xe6\xb7\xb1\xe5\x9c\xb3\xe5\xb8\x82\xe9\xbe\x99\xe5\xb2\x97\xe5\x8c\xba\xe9\xbe\x99\xe6\xa0\xbc\xe8\xb7\xaf303\xe5\x8f\xb7","uaIsCpadaily":"true","signInstanceWid":str(signInstanceWid),"extraFieldItems":[{"extraFieldItemValue":"\xe5\x90\xa6","extraFieldItemWid":str(awid)},{"extraFieldItemValue":"\xe5\x90\xa6","extraFieldItemWid":str(bwid)}]}
    payload = {"appVersion":"9.0.12","systemName":"android","bodyString":bodystr,"sign":getSign(bodyString),"model":"MI11","lon":114.222667,"calVersion":"firstv","systemVersion":"11","deviceId":deviceId+"XiaomiMI11","userId":username,"version":"first_v2","lat":22.691832}
    response = session.post(url, headers=header, json=payload)
    print(response.text)


if __name__ == '__main__':
    username = os.environ["USERNAME"]
    password = os.environ["PASSWORD"]
    deviceId = os.environ["DEVICEID"]
    username = username.split("&")
    password = password.split("&")
    deviceId = deviceId.split("&")
    for i in range(len(username)):
        getLogin(username[i],password[i])
        getInfos()
        getForm(signInstanceWid,signWid)
        submitForm(signInstanceWid,awid,bwid,username[i],deviceId[i])
