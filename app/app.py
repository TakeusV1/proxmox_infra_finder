from config import *

from flask import *
from flask_login import *

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

from proxmoxer import ProxmoxAPI

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config.from_object(Configuration)

db = SQLAlchemy(app)

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

class CreateForm(FlaskForm):
    username = StringField(validators=[DataRequired(),Length(max=128)])
    password = PasswordField(validators=[DataRequired(),Length(max=128)])
    is_admin = BooleanField(validators=[])

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

@app.route("/dashboard")
@login_required
def dashboard():
    form = SearchForm()
    return render_template("dash.html",title="PIL - Dashboard",app_version=app_version,form=form)

@app.post('/dashboard')
@login_required
def search_engine():
    result = None
    cloudinit_network = None
    form = SearchForm()
    if form.validate_on_submit():
        
        pve_clusters = []
        for cluster in clusters.values():
            print(f"--> Cluster {cluster[0]} added.")
            try:
                pve_clusters.append(ProxmoxAPI(cluster[1], user=cluster[2], password=cluster[3], verify_ssl=cluster[4]))
            except:
                print(f"--> Cluster {cluster[0]} not available.")

        for cluster in pve_clusters:
            # IF VM (qemu)
            if int(form.type.data) == 1: 
                resources = cluster.cluster.resources.get()
                vm_cluster_info = next((resource for resource in resources if resource['type'] == 'qemu' and resource['name'] == form.name.data), None)
                if vm_cluster_info != None:
                    result = vm_cluster_info
                    result['config'] = cluster.nodes(vm_cluster_info['node']).qemu(vm_cluster_info['vmid']).config.get()
                    result['network'] = {item.split('=')[0]: item.split('=')[1] for item in result['config']['net0'].split(',')}
                    try:
                        cloudinit_network = cluster.nodes(vm_cluster_info['node']).qemu(vm_cluster_info['vmid']).cloudinit.dump.get(type='network')
                    except:
                        pass                        
                    break          
            
            # IF CT (lxc)
            elif int(form.type.data) == 2:           
                resources = cluster.cluster.resources.get()
                ct_cluster_info = next((resource for resource in resources if resource['type'] == 'lxc' and resource['name'] == form.name.data), None)
                if ct_cluster_info != None:
                    result = cluster.nodes(ct_cluster_info['node']).lxc(ct_cluster_info['vmid']).status.current.get()
                    result['config'] = cluster.nodes(ct_cluster_info['node']).lxc(ct_cluster_info['vmid']).config.get()    
                    result['network'] = {item.split('=')[0]: item.split('=')[1] for item in result['config']['net0'].split(',')}    
                    result['node'] = ct_cluster_info['node']
                    try:
                        result['pool'] = ct_cluster_info['pool']
                    except:
                        result['pool'] = "N/A"
                    break        

            elif int(form.type.data) == 3:
                resources = cluster.cluster.resources.get()
                host_cluster_info = next((resource for resource in resources if resource['type'] == 'node' and resource['node'] == form.name.data), None)
                if host_cluster_info != None:
                    result = host_cluster_info
                    result['status'] = cluster.nodes(form.name.data).status.get()
                    result['network'] = cluster.nodes(form.name.data).network.get()
                    result['disks'] = cluster.nodes(form.name.data).disks.list.get()
                    result['version'] = cluster.nodes(form.name.data).version.get() 
        
            if result != None:
                break
        
        if result == None:
            return redirect(url_for('dashboard'))
        
    cluster_name = cluster.cluster.status.get()[0]['name']
    
    return render_template(
        "dash.html",
        title="PIL - Dashboard",
        app_version=app_version,
        form=form,result=result,
        type=int(form.type.data),
        cluster=cluster_name,
        ostype_img=ostype_img,
        ostype_kvm=ostype_kvm,
        cloudinit_network=cloudinit_network,
    )

@app.route('/dashboard/admin')
@login_required
def admin():
    if current_user.admin == False:
        return abort(403)
    
    db_users = User.query.all()
    form_create = CreateForm()
    
    return render_template(
        "admin.html",
        title="PIL - Admin",
        app_name=app_name,
        app_debug=app_debug,
        app_version=app_version,
        app_release_date=app_release_date,
        admin_dash=True,
        db_users=db_users,
        form_create=form_create,
    )

@app.post('/dashboard/admin/user/add')
@login_required
def add_user():
    if current_user.admin == False:
        return abort(403)
    
    form = CreateForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            return 'user exist'
        db.session.add(User(username=form.username.data,password=generate_password_hash(form.password.data),admin=form.is_admin.data))
        db.session.commit()
        return redirect(url_for('admin'))
    return 'problem ):'

@app.get('/dashboard/admin/user/<int:userid>/delete')
@login_required
def rem_user(userid):
    if current_user.admin == False:
        return abort(403)

    db.session.delete(User.query.filter_by(id=userid).first())
    db.session.commit()
    return redirect(url_for('admin'))