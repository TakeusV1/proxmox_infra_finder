from app import app
from config import app_debug,app_ip,app_port

if __name__ == '__main__':
    app.run(host=app_ip, port=app_port, debug=app_debug)