import azure.functions as func
from mcp_server import asgi_app

app = func.AsgiFunctionApp(
    app=asgi_app,
    http_auth_level=func.AuthLevel.ANONYMOUS,
)
