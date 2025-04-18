from app import app  # or whatever your main file is called
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Mount app under /factory
application = DispatcherMiddleware(Flask('dummy_app'), {
    '/factory': app
})
