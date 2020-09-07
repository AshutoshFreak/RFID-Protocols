import flask
import json
app = flask.Flask(__name__)

@app.route('/function/<variable>', methods=['GET'])
def function(variable):
    ret = {'ct': variable}
    return ret

if __name__ == '__main__':
    app.run(host='localhost', port=1024)
