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
from flask import request
from flask_wtf import CSRFProtect

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
        flask_app = app.create_app(config)
        
        # Setup CSRF protection for the whole application
        csrf = CSRFProtect()
        csrf.init_app(flask_app)

        # Exempt API routes from CSRF protection
        @flask_app.before_request
        def csrf_exempt_api():
            if request.path.startswith('/api/'):
                csrf.exempt(request.view_function)
            # Log request info
            logger.debug('Headers: %s', request.headers)
            logger.debug('Body: %s', request.get_data())

        logger.info("Flask application created successfully.")
        return flask_app
    except Exception as e:
        logger.error("Failed to create Flask application.", exc_info=True)
        raise e

