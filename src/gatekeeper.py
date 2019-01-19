import configparser
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from functools import wraps

import pony.orm.dbapiprovider
import requests
import tldextract
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session)
from passlib.context import CryptContext
from pony.orm import *
from wtforms import Form, PasswordField, StringField, validators
from wtforms.csrf.session import SessionCSRF

config = configparser.ConfigParser()
config.read('config.ini')
MAIN_CONFIG = config['main']
PRIVATE_ROUTES = config['routes']
PUBLIC_ROUTES = config['public-routes']
ALLOW_REGISTRATION = MAIN_CONFIG['AllowRegistration'] == 'yes'
DEBUG = MAIN_CONFIG['Debug'] == 'yes'
MAIN_DOMAIN = MAIN_CONFIG['Domain']

if 'Subdomain' in MAIN_CONFIG:
    LINK_DOMAIN = MAIN_CONFIG['Subdomain'] + '.' + MAIN_DOMAIN
else:
    LINK_DOMAIN = MAIN_DOMAIN

if 'AhSubdomain' in MAIN_CONFIG:
    AH_SUBDOMAIN = MAIN_CONFIG['AhSubdomain']
    AH_DOMAIN = AH_SUBDOMAIN + "." + MAIN_DOMAIN
else:
    AH_SUBDOMAIN = None
    AH_DOMAIN = LINK_DOMAIN

no_redir = [None, 'login', 'register']

app = Flask(__name__, static_folder=None)
app.secret_key = MAIN_CONFIG['SecretKey'].encode()
app.config['SERVER_NAME'] = LINK_DOMAIN
app.url_map.subdomain_matching = True
app.static_folder = 'static'
app.add_url_rule(
    '/static/<path:filename>',
    endpoint='static',
    subdomain='',
    view_func=app.send_static_file)

pwd_context = CryptContext(
    schemes=["pbkdf2_sha512"],
    deprecated="auto",
)

sql_debug(DEBUG)
db = Database()

USE_MYSQL = "MYSQL_ROOT_PASSWORD" in os.environ
if USE_MYSQL:
    MYSQL_HOST = 'db'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD")
    MYSQL_DB = os.environ.get("MYSQL_DATABASE", "gatekeeper")
    tries = 0
    connected = False
    while tries <= 5 and not connected:
        tries += 1
        try:
            db.bind(
                provider='mysql',
                host=MYSQL_HOST,
                user=MYSQL_USER,
                passwd=MYSQL_PASSWORD,
                db=MYSQL_DB)
            break
        except pony.orm.dbapiprovider.OperationalError as e:
            if tries == 5:
                raise e
            print("Waiting for database ...")
            time.sleep(7)

else:
    db.bind(provider='sqlite', filename='gatekeeper.db', create_db=True)


class Account(db.Entity):
    name = Required(str)
    username = Required(str)
    password = Required(str)


db.generate_mapping(create_tables=True)


@db_session
def create_new_user(**args):
    args['password'] = pwd_context.encrypt(args['password'])
    Account(**args)
    commit()


@db_session
def get_account_count():
    return len(Account.select())


if get_account_count() == 0:
    create_new_user(
        name=os.environ['GK_DEFAULT_NAME'],
        username=os.environ['GK_DEFAULT_USERNAME'],
        password=os.environ['GK_DEFAULT_PASSWORD'])


class SecureForm(Form):

    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = app.secret_key
        csrf_time_limit = timedelta(minutes=20)


class LoginForm(SecureForm):
    username = StringField(
        'Username', [validators.required(),
                     validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.required()])


class RegisterForm(SecureForm):
    name = StringField('Real Name', [validators.required()])
    username = StringField('Username', [validators.required()])
    password = PasswordField('Password', [
        validators.required(),
        validators.Length(min=6),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


@app.before_request
@db_session
def get_user():
    if 'userid' in session:
        g.user = Account.get(id=session['userid'])


def safe_next_url(url):
    extracted = tldextract.extract(url.lower())
    domain = extracted.registered_domain
    if domain != '' and domain != MAIN_DOMAIN:
        return "/"
    return url


def requires_auth(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'userid' not in session:
            next = safe_next_url(request.url)
            return redirect("https://" + AH_DOMAIN + "/Login?" +
                            urllib.parse.urlencode({
                                'next': next
                            }))
        return f(*args, **kwargs)

    return decorated


@app.route("/Login", methods=['GET', 'POST'], subdomain="")
@db_session
def login():
    next = request.args.get('next') if (
        request.args.get('next') not in no_redir) else '/'
    next_url = safe_next_url(next)
    form = LoginForm(request.form, meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        c = Account.get(username=form.username.data.lower())
        if not c or not pwd_context.verify(form.password.data, c.password):
            flash("Incorrect username or password.")
            return render_template(
                "login.html",
                form=form,
                next=next,
                allow_registration=ALLOW_REGISTRATION)
        session['userid'] = c.id
        return redirect(next_url)
    else:
        return render_template(
            "login.html",
            form=form,
            next=next,
            allow_registration=ALLOW_REGISTRATION)


@app.route("/Logout", subdomain="")
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
    if not ALLOW_REGISTRATION:
        return abort(404)
    next = request.args.get('next') if (
        request.args.get('next') not in no_redir) else 'catch_all'
    next_url = safe_next_url(next)
    form = RegisterForm(request.form, meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        c = create_new_user(
            name=form.name.data,
            username=form.username.data.lower(),
            password=form.password.data)
        commit()
        session['userid'] = c.id
        flash("You have successfully registered.")
        return redirect(next_url)
    else:
        return render_template("register.html", form=form)


@app.route("/", subdomain="")
@requires_auth
@db_session
def home():
    return render_template("home.html")


@app.route(
    "/",
    defaults={"path": ""},
    methods=['GET', 'POST'],
    subdomain="<subdomain>")
@app.route("/<string:path>", methods=['GET', 'POST'], subdomain="<subdomain>")
@app.route("/<path:path>", methods=['GET', 'POST'], subdomain="<subdomain>")
def catch_all(path, subdomain):
    subdomain = subdomain.lower()
    if subdomain in PRIVATE_ROUTES:
        return private_catch_all(path, subdomain)
    elif subdomain in PUBLIC_ROUTES:
        return proxy(PUBLIC_ROUTES[subdomain])
    return abort(404, "No endpoint [%s]" % subdomain)


@requires_auth
def private_catch_all(path, subdomain):
    return proxy(PRIVATE_ROUTES[subdomain])


def proxy(endpoint, *args, **kwargs):
    try:
        resp = requests.request(
            method=request.method,
            url=endpoint + request.full_path,
            headers={
                key: value for (key, value) in request.headers if key != 'Host'
            },
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=True,
            timeout=int(os.environ.get("GK_TIMEOUT", 5)))
    except requests.exceptions.ConnectionError:
        # HTTP 502: Bad Gateway
        return abort(502)
    except requests.exceptions.ReadTimeout:
        # HTTP 504: Gateway Timeout
        return abort(504)
    excluded_headers = [
        'content-encoding', 'content-length', 'transfer-encoding', 'connection'
    ]
    headers = [(name, value)
               for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]
    response = Response(resp.content, resp.status_code, headers)
    return response


if AH_SUBDOMAIN:
    app.add_url_rule(
        "/Login",
        "login",
        login,
        subdomain=AH_SUBDOMAIN,
        methods=['GET', 'POST'])
    app.add_url_rule("/Logout", "logout", logout, subdomain=AH_SUBDOMAIN)
    app.add_url_rule(
        "/Register",
        "register",
        register,
        subdomain=AH_SUBDOMAIN,
        methods=['GET', 'POST'])
    app.add_url_rule("/", "home", home, subdomain=AH_SUBDOMAIN)
    app.add_url_rule(
        '/static/<path:filename>',
        endpoint='static',
        subdomain=AH_SUBDOMAIN,
        view_func=app.send_static_file)


def get_gatekeeper_info():
    host = request.host.split(":")[0]
    return "gatekeeper at %s" % host


@app.errorhandler(502)
def bad_gateway(error):
    error_p = str(error).split("502 Bad Gateway: ")[1]
    return render_template(
        'error.html', error_h1="Bad Gateway", error_p=error_p), 502


@app.errorhandler(404)
def page_not_found(error):
    error_p = str(error).split("404 Not Found: ")[1]
    return render_template(
        'error.html', error_h1="Page not Found", error_p=error_p), 404


app.jinja_env.globals.update(get_gatekeeper_info=get_gatekeeper_info)

if __name__ == "__main__":
    app.run(host="0.0.0.0")
