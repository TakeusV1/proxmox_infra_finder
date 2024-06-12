from config import *

from flask import *
from flask_login import *

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

from proxmoxer import ProxmoxAPI

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config.from_object(Configuration)

db = SQLAlchemy(app)

active_cluster = []
for cluster in pve_clusters.values():
    print(f"--> Cluster {cluster[0]} added.")
    cluster[0] = ProxmoxAPI(cluster[1], user=cluster[2], password=cluster[3], verify_ssl=cluster[4])
    active_cluster.append(cluster[0])

#############################
###### DATABASE MODELS ######

class User(UserMixin, db.Model):
    id = db.Column(db.Integer(),primary_key=True,unique=True)
    username = db.Column(db.String(16))
    password = db.Column(db.String(32),unique=True)
    admin = db.Column(db.Boolean())
    
with app.app_context():
    db.create_all()

#########################
##### FORMS MODELS ######

class AuthForm(FlaskForm):
    username = StringField(validators=[DataRequired(),Length(max=128)])
    password = PasswordField(validators=[DataRequired(),Length(max=128)])

class SearchForm(FlaskForm):
    name = StringField(validators=[DataRequired(),Length(max=128)])
    type = SelectField(validators=[DataRequired()],choices=[(1, 'VM'), (2, 'CT'), (3, 'Host')])

#############################
######## SYSTEM ROUTES ######

@app.before_request
def before_request():
    if app_maintenance:
        return abort(503)

@app.route('/app_info')
def route_app_info():
    response = make_response(jsonify({'app_name': app_name, 'app_version':app_version,'release_date':app_release_date,'app_maintenance':app_maintenance,'app_debug':app_debug}), 200)
    return response

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()

############################
######## BASE ROUTES #######

@app.route('/',methods=['GET','POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    
    form = AuthForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user != None and check_password_hash(pwhash=user.password,password=form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))        
        return render_template("home.html",title="PIL - Login",app_version=app_version,form=form,fpass=True)
    return render_template("home.html",title="PIL - Login",app_version=app_version,form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))        

@app.route("/dashboard",methods=['GET','POST'])
@login_required
def dashboard():
    form = SearchForm()
    if form.validate_on_submit():
        for cluster in active_cluster:
            
            if int(form.type.data) == 1:
                vm_details = None
                for node in cluster.nodes.get():
                    node_name = node['node']
                    for vm in cluster.nodes(node['node']).qemu.get():
                        if vm.get('name') == form.name.data:
                            vm_details = cluster.nodes(node_name).qemu(vm['vmid']).status.current.get()
                            vm_details['node'] = node_name
                            vm_details['config'] = cluster.nodes(node_name).qemu(vm['vmid']).config.get()
                            vm_details['pool'] = cluster.pools.get()
                            break
                    if vm_details:
                        return vm_details                
                return redirect(url_for("dashboard"))
            
            elif int(form.type.data) == 2:
                ct_details = None
                for node in cluster.nodes.get():
                    node_name = node['node']
                    for ct in cluster.nodes(node['node']).lxc.get():
                        if ct.get('name') == form.name.data:
                            container_details = cluster.nodes(node_name).lxc(ct['vmid']).status.current.get()
                            container_details['node'] = node_name
                            container_details['config'] = cluster.nodes(node_name).lxc(ct['vmid']).config.get()
                            container_details['pool'] = cluster.pools.get() 
                            break
                    if container_details:
                        return container_details                
                return redirect(url_for("dashboard"))

            elif int(form.type.data) == 3:
                pass
            
    return render_template("dash.html",title="PIL - Dashboard",app_version=app_version,is_dash=True,form=form)

@app.route("/dashboard/search")
@login_required
def search_engine():
    return 'ok'