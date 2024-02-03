from flask import Flask, render_template, request
import pandas as pd
import pickle
from sklearn.metrics import accuracy_score


app = Flask(__name__, template_folder='templates')
print("Intrusion Detection System is live on the Wi-Fi Interface.....\nIDS is running without any errors!")

fields = [
    {
      "format": "default",
      "name": "duration",
      "type": "number",
      "description": "duration of connection in seconds"
    },
    {
      "format": "default",
      "name": "protocol_type",
      "type": "string",
      "description": "connection protocol (tcp, udp, icmp)"
    },
    {
      "format": "default",
      "name": "service",
      "type": "string",
      "description": "dst port mapped to service (E.G: http, ftp,..)"
    },
    {
      "format": "default",
      "name": "flag",
      "type": "string",
      "description": "normal or error status flag of connection"
    },
    {
      "format": "default",
      "name": "src_bytes",
      "type": "number",
      "description": "number of databytes from src to dst"
    },
    {
      "format": "default",
      "name": "dst_bytes",
      "type": "any",
      "description": "bytes from dst to src"
    },
    {
      "format": "default",
      "name": "land",
      "type": "number",
      "description": "1 if connection is from/to the same host/port; else 0"
    },
    {
      "format": "default",
      "name": "wrong_fragment",
      "type": "number",
      "description": "number of 'wrong' fragments (values 0,1,3)"
    },
    {
      "format": "default",
      "name": "urgent",
      "type": "number",
      "description": "number of urgent packets"
    },
    {
      "format": "default",
      "name": "hot",
      "type": "number",
      "description": "number of hot indicators"
    },
    {
      "format": "default",
      "name": "num_failed_logins",
      "type": "number",
      "description": "number of failed login attempts"
    },
    {
      "format": "default",
      "name": "logged_in",
      "type": "number",
      "description": "1 if successfully logged in; 0 otherwise"
    },
    {
      "format": "default",
      "name": "lnum_compromised",
      "type": "number",
      "description": "number of compromised conditions"
    },
    {
      "format": "default",
      "name": "lroot_shell",
      "type": "number",
      "description": "1 if root shell is obtained; 0 otherwise"
    },
    {
      "format": "default",
      "name": "lsu_attempted",
      "type": "number",
      "description": "1 if su root command attempted; 0 otherwise"
    },
    {
      "format": "default",
      "name": "lnum_root",
      "type": "number",
      "description": "number of root accesses"
    },
    {
      "format": "default",
      "name": "lnum_file_creations",
      "type": "number",
      "description": "number of file creation operations"
    },
    {
      "format": "default",
      "name": "lnum_shells",
      "type": "number",
      "description": "number of shell prompts "
    },
    {
      "format": "default",
      "name": "lnum_access_files",
      "type": "number",
      "description": "number of operations on access control files"
    },
    {
      "format": "default",
      "name": "lnum_outbound_cmds",
      "type": "number",
      "description": "number of outbound commands in an ftp session"
    },
    {
      "format": "default",
      "name": "is_host_login",
      "type": "number",
      "description": "1 if the login belongs to the hot list; 0 otherwise "
    },
    {
      "format": "default",
      "name": "is_guest_login",
      "type": "number",
      "description": "1 if the login is a guest login; 0 otherwise"
    },
    {
      "format": "default",
      "name": "count",
      "type": "number",
      "description": "number of connections to the same host as the current connection in the past two seconds"
    },
    {
      "format": "default",
      "name": "srv_count",
      "type": "number",
      "description": "number of connections to the same service as the current connection in the past two seconds"
    },
    {
      "format": "default",
      "name": "serror_rate",
      "type": "number",
      "description": "% of connections that have SYN errors"
    },
    {
      "format": "default",
      "name": "srv_serror_rate",
      "type": "number",
      "description": "% of connections that have SYN errors "
    },
    {
      "format": "default",
      "name": "rerror_rate",
      "type": "number",
      "description": "% of connections that have REJ errors"
    },
    {
      "format": "default",
      "name": "srv_rerror_rate",
      "type": "number",
      "description": "% of connections that have REJ errors"
    },
    {
      "format": "default",
      "name": "same_srv_rate",
      "type": "number",
      "description": "% of connections to the same service"
    },
    {
      "format": "default",
      "name": "diff_srv_rate",
      "type": "number",
      "description": "% of connections to different services"
    },
    {
      "format": "default",
      "name": "srv_diff_host_rate",
      "type": "number",
      "description": "% of connections to different hosts"
    },
    {
      "format": "default",
      "name": "dst_host_count",
      "type": "number",
      "description": "count of connections having same dst host"
    },
    {
      "format": "default",
      "name": "dst_host_srv_count",
      "type": "number",
      "description": "count of connections having same dst host and using same service"
    },
    {
      "format": "default",
      "name": "dst_host_same_srv_rate",
      "type": "number",
      "description": "% of connections having same dst port and using same service"
    },
    {
      "format": "default",
      "name": "dst_host_diff_srv_rate",
      "type": "number",
      "description": "% of different services on current host"
    },
    {
      "format": "default",
      "name": "dst_host_same_src_port_rate",
      "type": "number",
      "description": "% of connections to current host having same src port"
    },
    {
      "format": "default",
      "name": "dst_host_srv_diff_host_rate",
      "type": "number",
      "description": "% of connections to same service coming from different hosts"
    },
    {
      "format": "default",
      "name": "dst_host_serror_rate",
      "type": "number",
      "description": "% of connections to current host that have S0 error"
    },
    {
      "format": "default",
      "name": "dst_host_srv_serror_rate",
      "type": "number",
      "description": "% of connections to current host and specified service that have an S0 error"
    },
    {
      "format": "default",
      "name": "dst_host_rerror_rate",
      "type": "number",
      "description": "% of connections to current host that have an RST error"
    },
    {
      "format": "default",
      "name": "dst_host_srv_rerror_rate",
      "type": "number",
      "description": "% of connections to the current host and specified service that have an RST error"
    },
    {
      "format": "default",
      "name": "label",
      "type": "string",
      "description": "specifies whether normal traffic or attack in the network"
    }
]

@app.route("/")
def index():
  return render_template('index.html')

@app.route("/features")
def features():
  df = pd.read_csv('dataset/kddcup.csv')
  df_head = df.head(4)
  table_html = df_head.to_html(classes='table table-striped', index=False)
  return render_template('features.html', table_html=table_html, fields=fields)


@app.route("/pda")
def pda():
  return render_template('pda.html')

@app.route("/results", methods=['POST'])
def results():
  if request.method == 'POST':
    duration = float(request.form['duration'])
    protocol_type = request.form['protocolType']
    service = request.form['service']
    flag = request.form['flag']
    src_bytes = float(request.form['srcBytes'])
    dst_bytes = float(request.form['dstnBytes'])
    wrong_fragment = float(request.form['wrongFragment'])
    logged_in = float(request.form['loggedIn'])
    srv_count = float(request.form['samePortCount'])
    dst_host_count = float(request.form['sameDstnCount'])
    attackType = request.form['attackType']

    label_encoders = {}
    categorical_cols = ['protocol_type', 'service', 'flag']

    dt = pickle.load(open('ML Models/decision_tree_model.pkl', 'rb'))
    knn = pickle.load(open('ML Models/knn_model.pkl', 'rb'))
    lr = pickle.load(open('ML Models/logistic_regression_model.pkl', 'rb'))
    rf = pickle.load(open('ML Models/random_forest_model.pkl', 'rb'))
    for col in categorical_cols:
      label_encoders[col] = pickle.load(open(f'ML Models/{col}_label_encoder.pkl', 'rb'))
    try:
      protocol_type = label_encoders['protocol_type'].transform([protocol_type])[0]
      service = label_encoders['service'].transform([service])[0]
      flag = label_encoders['flag'].transform([flag])[0]
    except ValueError as e:
      protocol_type = 0  
      service = 0 
      flag = 0
      print(f"Error converting label: {e}")
    data = [[duration, protocol_type, service, flag, src_bytes, dst_bytes, wrong_fragment, logged_in, srv_count, dst_host_count]]
    dt_prediction = dt.predict(data)[0]
    knn_prediction = knn.predict(data)[0]
    lr_prediction = lr.predict(data)[0]
    rf_prediction = rf.predict(data)[0]
    y_true = [attackType]  
    dt_accuracy = accuracy_score(y_true, [dt_prediction])
    knn_accuracy = accuracy_score(y_true, [knn_prediction])
    lr_accuracy = accuracy_score(y_true, [lr_prediction])
    rf_accuracy = accuracy_score(y_true, [rf_prediction])
        
    return render_template('results.html', dt_prediction=dt_prediction, knn_prediction=knn_prediction, lr_prediction=lr_prediction, rf_prediction=rf_prediction, dt_accuracy=dt_accuracy, knn_accuracy=knn_accuracy, rf_accuracy=rf_accuracy, lr_accuracy=lr_accuracy)


if __name__ == '__main__':
    app.run(port=5000, debug=True)