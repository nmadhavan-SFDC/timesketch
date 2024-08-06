from authlib.integrations.flask_client import OAuth
from flask import current_app
import requests

oauth = OAuth()
def setup_oauth(app):
    oauth.init_app(app)
    oauth_provider = oauth.register(
        name='oauth_provider',
        server_metadata_url=app.config['OAUTH_METADATA_URL'],
        client_id=app.config['OAUTH_CLIENT_ID'],
        client_secret=app.config['OAUTH_CLIENT_SECRET'],
        client_kwargs={
            'scope': app.config['OAUTH_SCOPES']
        }
    )
    return oauth_provider
