from flask import Flask
from app import app  # replace with your actual app filename

from werkzeug.middleware.dispatcher import DispatcherMiddleware

application = DispatcherMiddleware(Flask('dummy_app'), {
    '/factory': app
})
