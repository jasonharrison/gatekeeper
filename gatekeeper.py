import configparser
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from functools import wraps

import requests
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session)
from passlib.context import CryptContext
from pony.orm import *
from werkzeug.urls import url_parse
from wtforms import Form, PasswordField, StringField, validators
from wtforms.csrf.session import SessionCSRF

config = configparser.ConfigParser()
config.read('config.ini')
main_config = config['main']
route_config = config['routes']

DEBUG = main_config['Debug'] == 'yes'
MAIN_DOMAIN = main_config['Domain']
LINK_DOMAIN = main_config['Subdomain'] + '.' + MAIN_DOMAIN
no_redir = [None, 'login', 'register']

app = Flask(__name__, static_folder=None)
app.secret_key = main_config['SecretKey'].encode()
app.config['SERVER_NAME'] = LINK_DOMAIN
app.url_map.subdomain_matching = True
app.static_folder = 'static'
app.add_url_rule('/static/<path:filename>',
                                  endpoint='static',
                                  subdomain='',
                                  view_func=app.send_static_file)

pwd_context = CryptContext(
    schemes=["pbkdf2_sha512"],
    deprecated="auto",
)

sql_debug(DEBUG)
db = Database()
db.bind('sqlite', 'data.sqlite', create_db=True)


class Account(db.Entity):
    name = Required(str)
    username = Required(str)
    password = Required(str)


db.generate_mapping(create_tables=True)


class SecureForm(Form):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = app.secret_key
        csrf_time_limit = timedelta(minutes=20)


class LoginForm(SecureForm):
    username = StringField(
        'Username', [validators.required(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.required()])


class RegisterForm(SecureForm):
    name = StringField('Real Name', [validators.required()])
    username = StringField('Username', [validators.required()])
    password = PasswordField('Password', [validators.required(),
                                          validators.Length(min=6),
                                          validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')


@app.before_request
@db_session
def get_user():
    if 'userid' in session:
        g.user = Account.get(id=session['userid'])


def safe_next_url(url):
    if urllib.parse.urlparse(url).netloc.endswith(MAIN_DOMAIN):
        return url
    return "/"


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'userid' not in session:
            next = safe_next_url(request.url)
            return redirect("https://"+LINK_DOMAIN+"/Login?" + urllib.parse.urlencode({'next': next}))
        return f(*args, **kwargs)
    return decorated


@app.route("/Login", methods=['GET', 'POST'], subdomain="")
@db_session
def login():
    next = request.args.get('next') if (
        request.args.get('next') not in no_redir) else '/'
    next_url = safe_next_url(next)
    form = LoginForm(request.form,  meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        c = Account.get(username=form.username.data.lower())
        if not c:
            flash("Incorrect username or password.")
            return render_template("login.html", form=form, next=next)
        if not pwd_context.verify(form.password.data, c.password):
            flash("Incorrect username or password.")
            return render_template("login.html", form=form, next=next)
        session['userid'] = c.id
        return redirect(next_url)
    else:
        return render_template("login.html", form=form, next=next)


@app.route("/Logout", host="inet.jasonharrison.us")
def logout():
    next = request.args.get('next') if (
        request.args.get('next') not in no_redir) else ''
    next_url = safe_next_url(next)
    session.pop('userid', None)
    flash("You have been logged out.")
    return redirect(next_url)


@app.route("/Register", methods=['GET', 'POST'], subdomain="")
@db_session
def register():
    next = request.args.get('next') if (
        request.args.get('next') not in no_redir) else 'catch_all'
    next_url = safe_next_url(next)
    form = RegisterForm(request.form, meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        hash = pwd_context.encrypt(form.password.data)
        c = Account(name=form.name.data,
                    username=form.username.data.lower(), password=hash)
        commit()
        session['userid'] = c.id
        flash("You have successfully registered.")
        return redirect(next_url)
    else:
        return render_template("register.html", form=form)


@app.route("/", subdomain="")
@requires_auth
@db_session
def index():
    return render_template("index.html")


@app.route("/", defaults={"path": ""}, methods=['GET', 'POST'], subdomain="<subdomain>")
@app.route("/<string:path>", methods=['GET', 'POST'], subdomain="<subdomain>")
@app.route("/<path:path>", methods=['GET', 'POST'], subdomain="<subdomain>")
@requires_auth
def catch_all(path, subdomain):
    subdomain = subdomain.lower()
    if subdomain not in route_config:
        return abort(404, "No endpoint [%s]" % subdomain)
    return proxy(route_config[subdomain])


def proxy(endpoint, *args, **kwargs):
    try:
        resp = requests.request(
            method=request.method,
            url=endpoint + request.full_path,
            headers={key: value for (key, value)
                     in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=True,
            timeout=5
        )
    except requests.exceptions.ConnectionError:
        # HTTP 502: Bad Gateway
        return abort(502)
    except requests.exceptions.ReadTimeout:
        # HTTP 504: Gateway Timeout
        return abort(504)
    excluded_headers = ['content-encoding',
                        'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]
    response = Response(resp.content, resp.status_code, headers)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0")
