import gunicorn
import os
gunicorn.SERVER_SOFTWARE = os.environ.get('GK_SERVER_SOFTWARE', 'gatekeeper')
