##############################################
############# CONFIGURATION FILE #############

## Flask Server (For DEV)
app_ip = '127.0.0.1'
app_port = 80
app_debug = True
app_maintenance = False

app_name = 'proxmox_infra_locator'
app_version = 'V0.1'    
app_release_date = '06/2024'

class Configuration:
    # openssl rand -hex 32
    SECRET_KEY = 'changeme'
    # DB CONFIG
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db' #mysql+mysqlconnector://user:password@127.0.0.1/database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    # CK CONFIG
    SESSION_COOKIE_SECURE = False # SSL REQUIRED
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'