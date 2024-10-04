# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Entry point for the application."""
import logging

def create_app(config=None):
    """Create the Flask app instance that is used throughout the application."""

    # Set up logging to a file
    handler = logging.FileHandler('timesketch.log')  # Log to 'timesketch.log'
    handler.setLevel(logging.DEBUG)  # Set the logging level
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Get the logger and add the handler
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.info("Starting to create Flask application...")

    try:
        # Create Flask app
        flask_app = Flask(__name__)

        # Load configuration from timesketch.conf
        load_config(flask_app)

        # Override with environment variables (optional)
        flask_app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', flask_app.config.get('SECRET_KEY', 'default-secret-key'))
        flask_app.config['DEBUG'] = os.environ.get('DEBUG', flask_app.config.get('DEBUG', 'False')).lower() == 'true'

        # If a config dictionary is passed, update the app config with it
        if config:
            flask_app.config.update(config)

        # Initialize SAML within app context
        with flask_app.app_context():
            init_saml(flask_app)

        # Register blueprints
        flask_app.register_blueprint(auth_views)

        logger.info("Flask application created successfully.")
        return flask_app
    except Exception as e:
        logger.error("Failed to create Flask application.", exc_info=True)
        raise e

# This allows you to run the app directly with `python __init__.py`
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
