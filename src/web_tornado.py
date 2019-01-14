from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from gatekeeper import app
# from test import app
from tornado.log import enable_pretty_logging
enable_pretty_logging()

http_server = HTTPServer(WSGIContainer(app), ssl_options={
    'certfile': '/appdata/ssl/cert.pem',
    'keyfile': '/appdata/ssl/privkey.pem'
    })
http_server.listen(8443)
IOLoop.instance().start()
