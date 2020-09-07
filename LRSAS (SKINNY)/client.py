import requests
adr = 'http://localhost:1024/function/ashutosh'
r = requests.get(url=adr)
data = r.json()
print(data)
