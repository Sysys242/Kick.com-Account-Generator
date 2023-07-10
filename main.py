import tls_client, websocket, json
import random, string, requests
import threading
from colorama import Fore

proxies = open('input/proxies.txt', "r", encoding="utf-8").read().splitlines()
apiKey = input('Kopeechka Key> ')
prefix = ""

class Email:
    def __init__(self) -> None:
        pass

    def getEmail(self) -> str:
        response = requests.get(
            f'https://api.kopeechka.store/mailbox-get-email?api=2.0&site=kick.com&sender=kick&regex=&mail_type=outlook.fr&token={apiKey}',
            headers={
                'authority': 'api.kopeechka.store',
                'accept': '*/*',
                'accept-language': 'fr-FR,fr;q=0.6',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://kopeechka.store',
                'referer': 'https://kopeechka.store/',
                'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            }
        )
        self.mailId = response.json()['id']
        return response.json()['mail']
    
    def getOtpCode(self) -> str:
        response = requests.get(
            f'https://api.kopeechka.store/mailbox-get-message?full=1&id={self.mailId}&token={apiKey}',
            headers={
                'authority': 'api.kopeechka.store',
                'accept': '*/*',
                'accept-language': 'fr-FR,fr;q=0.6',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://kopeechka.store',
                'referer': 'https://kopeechka.store/',
                'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            }
        )
        if response.json()['status'] == "ERROR":
            return None
        else:
            return response.json()['fullmessage'].split('<div style="display: inline-block; padding: 12px 24px; background: #070809; border-radius: 8px; font-weight: 700; font-size: 18px;">')[1].split('</div>')[0]

class Kick:
    def __init__(self) -> None:
        self.mail = Email()
        self.email = self.mail.getEmail()
        self.log(f'Got Email: {self.email}')


        self.session = tls_client.Session(
            client_identifier="chrome_114",
            random_tls_extension_order=True
        )
        self.session.headers = {
            'authority': 'kick.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'fr-FR,fr;q=0.9',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        }
        self.proxy = "http://" + random.choice(proxies).replace('sessionid', str(random.randint(500,10000)))
        self.session.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.cookies = self.session.get('https://kick.com/').cookies
        self.log(f'Got Cookies: {self.session.cookies.get("XSRF-TOKEN")[:30]}')
    
    def log(self, text:str) -> None:
        if 1 == 2: print(text)

    def connectToWs(self) -> None:
        ws = websocket.WebSocket()
        ws.connect('wss://ws-us2.pusher.com/app/eb1d5f283081a78b932c?protocol=7&client=js&version=7.6.0&flash=false')
        while True:
            res = json.loads(ws.recv())
            if res["event"] == "pusher:connection_established":
                self.socketId = json.loads(res['data'])['socket_id']
                self.log(f'Got Socket Id: {self.socketId}')
                break
            else:
                print(res)
        ws.close()
    
    def reqTokenProvider(self) -> None:
        self.session.headers.update({
            "accept": "application/json, text/plain, */*",
            "authorization": f'Bearer {self.session.cookies.get("XSRF-TOKEN")}',
            'x-socket-id': self.socketId,
            'x-xsrf-token': self.session.cookies.get("XSRF-TOKEN")
        })
        response = self.session.get(
            'https://kick.com/kick-token-provider'
        )
        self.session.cookies.update(response.cookies)
        self.encryptedValidFrom = response.json()['encryptedValidFrom']
        self.nameFieldName = response.json()['nameFieldName']
    
    def sendOtpCode(self) -> None:
        response = self.session.post(
            'https://kick.com/api/v1/signup/send/email',
            json={
                    'email': self.email,
                }
        )
        self.log(f'Sent Otp Code | Status Code: {response.status_code}')
        if response.status_code == 204:
            self.log(f'Successfuly sent otp code to {self.email}')
        else:
            self.log(f'Failed to send otp code to {self.email}')

    def verifyEmail(self, code:str) -> bool:
        response = self.session.post(
            'https://kick.com/api/v1/signup/verify/code',
            json={
                'code': code,
                'email': self.email,
            }
        )
        self.log(f'Verication Request | Status Code: {response.status_code}')
        if response.status_code == 204:
            self.log(f'Successfuly verified the account | Status Code: {response.status_code}')
            self.session.cookies.update(response.cookies)
            return True
        else:
            self.log(f'Failed verifying the account | Status Code: {response.status_code}')
            return False
    
    def registerAccount(self) -> bool:
        self.passw = f"$y$y{''.join(random.choices(string.ascii_uppercase + string.digits, k=10))}$y$y"
        response = self.session.post(
            'https://kick.com/register',
            json={
                'birthdate': '03/03/1997',
                'username': f"{prefix}{''.join(random.choices(string.ascii_uppercase + string.digits, k=10))}",
                'email': self.email,
                'cf_captcha_token': '',
                'password': self.passw,
                'password_confirmation': self.passw,
                'agreed_to_terms': True,
                'newsletter_subscribed': False,
                'enable_sms_promo': False,
                'enable_sms_security': False,
                self.nameFieldName: '',
                '_kick_token_valid_from': self.encryptedValidFrom,
            }
        )
        self.log(f'Register Request | Status Code: {response.status_code}')
        if response.status_code == 201:
            self.log(f'Successfuly created the account | Status Code: {response.status_code}')
            self.session.cookies.update(response.cookies)
            return True
        else:
            self.log(f'Failed creating the account | Status Code: {response.status_code}')
            return False

    def generate(self) -> None:
        print(f'{Fore.LIGHTCYAN_EX}[CREATING] {self.email}{Fore.RESET}')
        self.connectToWs()
        self.reqTokenProvider()

        self.sendOtpCode()
        print(f'{Fore.LIGHTBLUE_EX}[OTP] {self.email}{Fore.RESET}')
        otpCode = None
        while otpCode == None:
            otpCode = self.mail.getOtpCode()
        self.log(f'Got OTP Code: {otpCode}')
        print(f'{Fore.LIGHTYELLOW_EX}[OTP] {self.email} | {otpCode}{Fore.RESET}')
        if self.verifyEmail(otpCode):
            if self.registerAccount():
                print(f'{Fore.LIGHTGREEN_EX}[CREATED] {self.email} | {self.passw}{Fore.RESET}')
                with open('output.txt', 'a') as f:
                    f.write(f'\n{self.email}:{self.passw}')
            else:
                print(f'{Fore.LIGHTRED_EX}[FAILED] {self.email} | {self.passw} | REGISTERATION{Fore.RESET}')
        else:
            print(f'{Fore.LIGHTRED_EX}[FAILED] {self.email} | {self.passw} | VERIFICATION{Fore.RESET}')

def gen():
    while True:
        try:
            kick = Kick()
            kick.generate()
        except:
            pass

if __name__ == "__main__":
    print("Baka gen by Sysy's")
    threadNum = int(input('Thread Number: '))
    for i in range(threadNum):
        threading.Thread(target=gen).start()