import logging

logger = logging.getLogger(__name__)

class CORSHeadersMiddleware:
    """Ensure CORS headers are always present, especially for OPTIONS requests"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        method = request.method
        logger.warning(f"CORS Middleware: {method} {path}")

        # Handle preflight OPTIONS requests
        if request.method == 'OPTIONS':
            logger.warning(f"Handling OPTIONS request for {path}")
            response = self._options_response()
            logger.warning(f"Returning OPTIONS response with CORS headers")
            return response

        response = self.get_response(request)

        # Always add CORS headers
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response['Access-Control-Max-Age'] = '3600'
        response['Access-Control-Expose-Headers'] = '*'

        return response

    def _options_response(self):
        """Return a 200 OK response for OPTIONS requests with CORS headers"""
        from django.http import HttpResponse
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response['Access-Control-Max-Age'] = '3600'
        response['Access-Control-Expose-Headers'] = '*'
        response.status_code = 200
        return response
