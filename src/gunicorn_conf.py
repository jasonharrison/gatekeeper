import gunicorn
import os
gunicorn.SERVER_SOFTWARE = 'gatekeeper'  # hide detailed gunicorn version info
bind = "0.0.0.0:8443"
certfile="/ssl/cert.pem"
keyfile="/ssl/privkey.pem"

