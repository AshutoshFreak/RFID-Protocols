import requests

fid = ''

def connect(to_call, param):
    adr = f'http://localhost:1024/{to_call}/{param}'
    r = requests.get(url=adr)
    return(r.json()['ct'])


def en(plaintext):
    return plaintext


def authenticate(m1m2):
    m1 = m1m2[:len(m1m2//2)]
    m2 = m1m2[len(m1m2//2):]
    if len(m1) != len(fid):
        print('Error: Incorrect Slicing')
        exit(1)
    m1 = int(m1)
    m2 = int(m2)
    r_dash = m1 ^ fid
    m2_dash = en(fid^id^r_dash)
    if m2_dash == m2:
        m3_dash = en(m2_dash^r_dash)
        return m3_dash
    else:
        print('Authentication Failed')
        exit(1)

if __name__ == '__main__':

    # Identification Phase
    to_call = 'identify'
    param = fid
    m1m2 = connect(to_call, param)
    
    # Authentication Phase
    m3_dash = authenticate(m1m2)
    to_call = 'authenticate'
    param = m3_dash
    adr = connect(to_call, param)

    # Update Phase
    fid = m1m2[:len(m1m2)//2]
    # Generate new key

    
    