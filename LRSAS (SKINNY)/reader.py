import flask
import json
app = flask.Flask(__name__)
fids = []
r = ''
m1 = ''
m2 = ''
m3 = ''
current_fid = ''
current_fid_old = ''

def en(plaintext):
    return plaintext

@app.route('/identify/<fid>', methods=['GET'])
def identify(fid):
    if fid in fids:
        m1 = str(fid^r)
        m2 = str(en(fid^id^r))
        m3 = en(m2^r)
        return {'ct': m1 + m2}
    else:
        return 1


@app.route('/authenticate/<m3_dash>', methods=['GET'])
def authenticate(m3_dash):
    if m3 == m3_dash:
        # Reimplement it
        current_fid = current_fid_old
        # update k_old
        fid_new = m1
        # generate k_new
        return 0
    else:
        return 1