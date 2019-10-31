from flask import Flask, redirect, render_template, request, session, url_for
import hashlib
import subprocess
import uuid

app = Flask(__name__)
app.secret_key = b'dev_key'
app.session_cookie_secure = True
app.session_cookie_httponly = True
app.config.from_pyfile('config.py', silent=True)
users = {}


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['uname']
        pword = request.form['pword']
        twofa = request.form['2fa']
        success = ""
        if uname in users:
            success = "Failure username exists"
        elif len(pword) < 8:
            success = "Failure password too short"
        else:
            m = hashlib.sha256()
            m.update(pword.encode('utf-8'))
            users[uname] = {}
            users[uname]['pword'] = m.digest()
            users[uname]['2fa'] = twofa
            success = "Success"
        return render_template('register.html', success=success)
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['uname']
        pword = request.form['pword']
        twofa = request.form['2fa']
        if uname not in users:
            return render_template('login.html', result="Incorrect")
        hashed_pword = users[uname]['pword']
        saved_twofa = users[uname]['2fa']
        if saved_twofa != twofa:
            return render_template('login.html', result="Two-Factor failure")
        m = hashlib.sha256()
        m.update(pword.encode('utf-8'))
        if hashed_pword != m.digest():
            return render_template('login.html', result="Incorrect")

        session['username'] = uname
        users[uname]['csrf'] = str(uuid.uuid4())
        return render_template('login.html', result="Success")
    else:
        return render_template('login.html')


@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if not session.get('username') or session['username'] not in users:
        return redirect(url_for('login'))

    csrf = users[session['username']]['csrf']
    if request.method == 'POST':
        users[session['username']]['csrf'] = str(uuid.uuid4())
        if 'csrf' not in request.form or request.form['csrf'] != csrf:
            return redirect(url_for('login'))
        csrf = users[session['username']]['csrf']

        inputtext = request.form['inputtext']
        with open('inputtext.txt', 'w+') as f:
            f.write(inputtext)
        misspelled = subprocess.check_output(
            ['./a.out', 'inputtext.txt',  'wordlist.txt']).decode('utf-8')[:-1]
        misspelled = ', '.join(misspelled.split('\n'))
        return render_template('spell_check.html',
                               textout=inputtext, misspelled=misspelled,
                               csrf=csrf)
    else:
        return render_template('spell_check.html', csrf=csrf)
