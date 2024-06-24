# Proxmox Infra Locator
>An application for locating clusters, hosts, VMs, pools... across an infrastructure composed of proxmox clusters.
>**This application is currently in BETA and should not be used in production. Don't hesitate to test it and report any problems (:**
## Features
- Locate VM *(QEMU)*
- Locate CT *(LXC)*
- Locate Nodes *(PVE)*
- Locate across multiple clusters
- Informations *(Base, Hardware, Network)*
## Screenshots
![all](https://github.com/TakeusV1/proxmox_infra_locator/assets/68923554/9ab2c050-a76d-4d83-86a6-b0f011853c8e)
## Installation
>https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-22-0
- check `requirements.txt` (`pip install -r requirements.txt` in venv).
- edit the `config.py`.
- run the `setup.py` web server to create the first admin user (then delete it).
