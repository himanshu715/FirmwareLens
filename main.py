from starlette.middleware.wsgi import WSGIMiddleware

from app import app as flask_app


# ASGI compatibility shim so platforms configured for `uvicorn main:app`
# can still serve the primary Flask application.
app = WSGIMiddleware(flask_app)
