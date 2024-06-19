##############################################
############# CONFIGURATION FILE #############

## Flask Server (For DEV)
app_ip = '127.0.0.1'
app_port = 80
app_debug = True
app_maintenance = False

app_name = 'proxmox_infra_locator'
app_version = 'V1.0'    
app_release_date = '06/2024'

ostype_kvm = {
    'l24':['linux', 'Linux 2.4'],
    'l26':['linux', 'Linux 2.6'],
    'win10':['windows', 'Windows 10/2016/2019'],
    'win11':['windows', 'Windows 11/2022/2025']
}
ostype_img = ['ubuntu', 'debian', 'alpine', 'windows']

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
    
clusters = {
    #1 : ["name", "<IPV4/DOMAIN>", "<username>@<realm>", "<password>", True], ## verify SSL True or False
    1 : ["taklab", "192.168.1.1", "pve_locator@pve", "password", False],
    2 : ['pve-test-01', "192.168.1.59", "root@pam", "password", False],
    3 : ['pve-test-02', "192.168.1.60", "root@pam", "password", False]
}