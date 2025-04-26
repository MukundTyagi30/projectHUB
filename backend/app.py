import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, send_file, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt  # Rename to avoid conflict with flask-jwt-extended
from flask_cors import CORS
import json
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import uuid
from functools import wraps
import bcrypt  # Add bcrypt import
import ssl  # Add SSL import

"""
TLS/HTTPS Configuration
-----------------------
This application uses TLS (Transport Layer Security) to secure all HTTP communications.
A self-signed certificate is used for development and testing purposes.

Certificate Generation:
The certificate was generated using the following OpenSSL command:

```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Parameters explained:
- req -x509: Generate a self-signed certificate (X.509 format)
- -newkey rsa:4096: Generate a new 4096-bit RSA key pair
- -nodes: No DES encryption (don't encrypt the private key with a passphrase)
- -out cert.pem: Output file for the certificate
- -keyout key.pem: Output file for the private key
- -days 365: Certificate validity period (1 year)
- -subj "/CN=localhost": Certificate subject (Common Name = localhost)
- -addext "subjectAltName=DNS:localhost,IP:127.0.0.1": 
    Add Subject Alternative Names (SANs) to specify valid hostnames and IPs

For production:
1. Use a certificate from a trusted Certificate Authority (CA)
2. Set proper certificate validation on both server and client side
3. Implement certificate rotation and renewal procedures
4. Consider using Let's Encrypt for free, trusted certificates
"""

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration - Using SQLite for easier setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projecthub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config["JWT_SECRET_KEY"] = "your-secret-key"  # Use the same secret key for JWT
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # Token expires in 1 hour
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)  # Refresh token expires in 30 days

# Security configuration
app.config['BCRYPT_ROUNDS'] = 12  # Work factor for bcrypt (higher is more secure but slower)

# SSL/TLS Configuration
app.config['SSL_ENABLED'] = True  # Set to False to disable HTTPS during development
app.config['SSL_CERT_PATH'] = os.path.join(os.path.dirname(__file__), 'ssl', 'cert.pem')
app.config['SSL_KEY_PATH'] = os.path.join(os.path.dirname(__file__), 'ssl', 'key.pem')

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize JWTManager
jwt = JWTManager(app)

# Add custom JWT verification middleware to allow legacy tokens
@app.before_request
def handle_legacy_jwt():
    # Only check endpoints that need JWT verification (skip login, register, etc.)
    if request.endpoint and any(x in request.endpoint for x in ['documents', 'chat']):
        # Check for the presence of the Authorization header
        auth_header = request.headers.get('Authorization')
        print(f"Middleware processing endpoint: {request.endpoint}")
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            print(f"Middleware received token: {token[:20]}...")
            
            # Try to pre-validate with pyjwt
            try:
                decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded.get('user_id')
                
                if user_id:
                    print(f"Middleware found legacy token for user_id: {user_id}")
                    
                    # This is a valid legacy token
                    from flask import _request_ctx_stack
                    from flask_jwt_extended.utils import get_jwt_identity, create_access_token
                    
                    # Check if Flask-JWT-Extended context is already set up
                    ctx = _request_ctx_stack.top
                    if not hasattr(ctx, 'jwt'):
                        # Need to create JWT object expected by get_jwt_identity()
                        print("Setting up Flask-JWT-Extended context with legacy token")
                        
                        # Create a properly structured JWT object with required fields
                        ctx.jwt = {
                            'sub': user_id,  # This is the identity used by get_jwt_identity()
                            'iat': decoded.get('iat', int(datetime.utcnow().timestamp())),
                            'nbf': decoded.get('nbf', int(datetime.utcnow().timestamp())),
                            'jti': decoded.get('jti', str(uuid.uuid4())),
                            'exp': decoded.get('exp', int((datetime.utcnow() + timedelta(days=1)).timestamp())),
                            'fresh': False,
                            'type': 'access',
                            # Add original user_id for compatibility
                            'user_id': user_id,
                            'legacy_token': True
                        }
                        
                        # Also need to create jwt_header for completeness
                        ctx.jwt_header = {'alg': 'HS256', 'typ': 'JWT'}
                        
                        print(f"Middleware set up JWT context with sub={user_id}")
                    else:
                        print("JWT context already exists")
            except Exception as e:
                # Not a valid legacy token, let Flask-JWT-Extended handle it
                print(f"Not a valid legacy token or error in middleware: {str(e)}")
                pass

# Add error handlers for JWT
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'message': 'Token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 'error',
        'message': 'Invalid token',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 'error',
        'message': 'Missing authorization token',
        'error': 'authorization_required'
    }), 401

# User model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with projects
    projects = db.relationship('Project', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }

# Project model
class Project(db.Model):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    progress = db.Column(db.Integer, default=0)  # 0-100 percentage
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    objectives = db.Column(db.Text, nullable=True)  # Stored as JSON string
    
    # Relationships
    team_members = db.relationship('ProjectTeamMember', backref='project', lazy=True, cascade="all, delete-orphan")
    tasks = db.relationship('Task', backref='project', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Project {self.name}>'
    
    def to_dict(self):
        # Parse objectives from string to list if it exists
        objectives_list = []
        if self.objectives:
            import json
            try:
                print(f"Objectives raw data: {self.objectives}")
                objectives_list = json.loads(self.objectives)
                print(f"Parsed objectives: {objectives_list}")
            except Exception as e:
                print(f"Error parsing objectives: {e}")
                # If it's a string but not valid JSON, treat it as a single objective
                if isinstance(self.objectives, str):
                    if ',' in self.objectives:
                        objectives_list = [obj.strip() for obj in self.objectives.split(',')]
                    else:
                        objectives_list = [self.objectives]
            
        # Build the project dictionary
        project_dict = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'startDate': self.start_date.isoformat() if self.start_date else None,
            'endDate': self.end_date.isoformat() if self.end_date else None,
            'dueDate': self.end_date.isoformat() if self.end_date else None,  # Include dueDate for frontend compatibility
            'priority': self.priority,
            'progress': self.progress,
            'user_id': self.user_id,
            'objectives': objectives_list,
            'teamMembers': [member.to_dict() for member in self.team_members],
            'tasks': [task.to_dict() for task in self.tasks]
        }
        print(f"Project {self.id} data: {project_dict}")
        return project_dict

# Project Team Members model
class ProjectTeamMember(db.Model):
    __tablename__ = 'project_team_members'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    member_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='Team Member')
    avatar = db.Column(db.String(200), nullable=True)
    
    def __repr__(self):
        return f'<TeamMember {self.member_name} for Project {self.project_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.member_name,
            'role': self.role or 'Team Member',
            'avatar': self.avatar or f"https://ui-avatars.com/api/?name={self.member_name.replace(' ', '+')}&background=random"
        }

# Task model
class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(20), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    assignee = db.Column(db.String(100), nullable=True)
    
    def __repr__(self):
        return f'<Task {self.title} for Project {self.project_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'dueDate': self.due_date.isoformat() if self.due_date else None,
            'completed': self.completed,
            'created_at': self.created_at.isoformat(),
            'project_id': self.project_id,
            'assignee': self.assignee
        }

# ChatMessage model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message_type = db.Column(db.String(20), default='message')  # 'message', 'system', etc.
    encrypted = db.Column(db.Boolean, default=False)  # Flag to indicate if the message is E2E encrypted
    
    # Relationships
    project = db.relationship('Project', backref=db.backref('chat_messages', lazy=True))
    user = db.relationship('User', backref=db.backref('sent_messages', lazy=True))

# Document model
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    tags = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    project = db.relationship('Project', backref=db.backref('documents', lazy=True))
    user = db.relationship('User', backref=db.backref('documents', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'filename': self.filename,
            'file_type': self.file_type,
            'description': self.description,
            'tags': self.tags,
            'uploaded_at': self.uploaded_at.isoformat(),
            'uploaded_by': self.user.name
        }

# Function to create tables
@app.before_first_request
def create_tables():
    db.create_all()
    sync_all_project_progress()

# Function to synchronize all project progress values with actual task completion
def sync_all_project_progress():
    projects = Project.query.all()
    updated_count = 0
    
    for project in projects:
        tasks = Task.query.filter_by(project_id=project.id).all()
        
        # Set progress based on task completion
        old_progress = project.progress
        if not tasks:
            # If no tasks, progress should be 0
            project.progress = 0
        else:
            completed_tasks = sum(1 for task in tasks if task.completed)
            project.progress = int((completed_tasks / len(tasks)) * 100)
        
        # Only count as updated if progress value changed
        if old_progress != project.progress:
            updated_count += 1
            print(f"Updated project {project.id} progress: {old_progress}% → {project.progress}%")
    
    db.session.commit()
    print(f"Synchronized progress for {updated_count} projects")

# Helper function to verify JWT token
def verify_token():
    token = request.headers.get('Authorization')
    
    print(f"Headers received: {request.headers}")
    print(f"Token: {token}")
    
    if not token:
        print("No token provided")
        return None, {'success': False, 'message': 'Token is missing'}, 401
    
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
            
        print(f"Decoding token: {token}")
        data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print(f"Decoded token data: {data}")
        
        current_user = User.query.filter_by(id=data['user_id']).first()
        
        if not current_user:
            print(f"User not found for ID: {data['user_id']}")
            return None, {'success': False, 'message': 'User not found'}, 401
            
        print(f"User authenticated: {current_user.name}")
        return current_user, None, None
    except Exception as e:
        print(f"Token validation error: {str(e)}")
        return None, {'success': False, 'message': f'Token is invalid: {str(e)}'}, 401

# Serve the HTML files
@app.route('/')
def index():
    return send_from_directory('../', 'creative-login.html')

@app.route('/signup')
def signup():
    return send_from_directory('../', 'projecthub-signup.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory('../', 'dashboard.html')

@app.route('/websocket-test')
def websocket_test():
    return send_from_directory('./', 'test_websocket.html')

@app.route('/admin')
def admin():
    return send_from_directory('static', 'admin.html')

@app.route('/verify')
def verify():
    return send_from_directory('static', 'verify-account.html')

# Secure password hashing functions
def hash_password(password):
    """
    Hash a password using bcrypt with automatic salting
    
    This is significantly more secure than SHA-256 because:
    1. bcrypt is designed specifically for password hashing and is resistant to brute force attacks
    2. It automatically incorporates a random salt to protect against rainbow table attacks
    3. It uses a configurable work factor that can be adjusted as hardware gets faster
    4. The algorithm is deliberately slow to prevent high-volume brute force attempts
    
    Args:
        password (str): The plaintext password
        
    Returns:
        str: The hashed password with salt incorporated
    """
    # Convert the password to bytes if it's not already
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate a salt and hash the password
    salt = bcrypt.gensalt(rounds=app.config.get('BCRYPT_ROUNDS', 12))
    hashed = bcrypt.hashpw(password, salt)
    
    # Return string representation for database storage
    return hashed.decode('utf-8')

def verify_password(stored_hash, provided_password):
    """
    Verify a password against its hash
    
    Args:
        stored_hash (str): The hashed password stored in the database
        provided_password (str): The password provided during login attempt
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    # Convert inputs to bytes if they're not already
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    if isinstance(provided_password, str):
        provided_password = provided_password.encode('utf-8')
    
    # Use bcrypt's built-in comparison function which is timing-attack resistant
    return bcrypt.checkpw(provided_password, stored_hash)

def is_bcrypt_hash(pw_hash):
    """
    Check if a hash is in bcrypt format
    
    Args:
        pw_hash (str): The hash to check
        
    Returns:
        bool: True if it's a bcrypt hash, False otherwise
    """
    return pw_hash.startswith('$2b$') or pw_hash.startswith('$2a$') or pw_hash.startswith('$2y$')

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'success': False, 'message': 'Email already registered'}), 400
    
    # Hash password with bcrypt (more secure than the previous SHA-256)
    hashed_password = hash_password(data['password'])
    
    # Create new user
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Missing email or password'}), 400
    
    # Check if user exists
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    # Determine which verification method to use based on the hash format
    password_verified = False
    
    if is_bcrypt_hash(user.password):
        # Verify with bcrypt
        password_verified = verify_password(user.password, data['password'])
    else:
        # Fall back to werkzeug for older passwords
        password_verified = check_password_hash(user.password, data['password'])
        
        # If verification succeeds with the old method, upgrade to bcrypt
        if password_verified:
            user.password = hash_password(data['password'])
            db.session.commit()
            print(f"Upgraded password hash to bcrypt for user {user.id}")
    
    if not password_verified:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    # Generate JWT token using Flask-JWT-Extended
    from flask_jwt_extended import create_access_token
    
    access_token = create_access_token(identity=user.id)
    
    # For backward compatibility with existing code, we're also
    # creating a legacy token. This is important for existing
    # endpoints that still use the old token format.
    legacy_token = pyjwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    print(f"Generated JWT token for user {user.id}: {access_token[:20]}...")
    
    # IMPORTANT: The frontend expects the token in the 'token' field
    # So we return the legacy_token as 'token' to maintain compatibility
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': legacy_token,  # Keep using legacy token for frontend compatibility
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    }), 200

@app.route('/api/admin/users', methods=['GET'])
def get_users():
    # In a real app, this should be protected with admin authentication
    try:
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users]
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Example protected route
@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'success': False, 'message': 'Token is missing'}), 401
    
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
            
        data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.filter_by(id=data['user_id']).first()
        
        if not current_user:
            return jsonify({'success': False, 'message': 'User not found'}), 401
            
        return jsonify({
            'success': True,
            'message': 'Protected data retrieved',
            'user': {
                'id': current_user.id,
                'name': current_user.name,
                'email': current_user.email
            }
        }), 200
    except:
        return jsonify({'success': False, 'message': 'Token is invalid'}), 401

@app.route('/api/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'success': False, 'message': 'No email provided'}), 400
    
    # Check if user exists
    user = User.query.filter_by(email=data['email']).first()
    
    return jsonify({
        'success': True,
        'exists': user is not None
    }), 200

# Project API Routes
@app.route('/api/projects', methods=['POST'])
def create_project():
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    data = request.get_json()
    print("Received project data:", data)
    
    # Validate input
    required_fields = ['name', 'startDate', 'endDate', 'priority']
    for field in required_fields:
        if field not in data:
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    try:
        # Handle objectives if provided
        objectives_json = None
        if 'objectives' in data and isinstance(data['objectives'], list):
            import json
            objectives_json = json.dumps(data['objectives'])
            print("Objectives JSON:", objectives_json)
        
        # Create new project
        new_project = Project(
            name=data['name'],
            description=data.get('description', ''),
            start_date=datetime.fromisoformat(data['startDate']).date(),
            end_date=datetime.fromisoformat(data['endDate']).date(),
            priority=data['priority'],
            progress=data.get('progress', 0),
            objectives=objectives_json,
            user_id=current_user.id
        )
        
        db.session.add(new_project)
        db.session.flush()  # Get the project ID
        print(f"Created project with ID: {new_project.id}")
        
        # Add team members if provided
        if 'teamMembers' in data and isinstance(data['teamMembers'], list):
            print(f"Processing {len(data['teamMembers'])} team members")
            for member in data['teamMembers']:
                print(f"Processing team member: {member}")
                if isinstance(member, dict) and 'name' in member:
                    team_member = ProjectTeamMember(
                        project_id=new_project.id,
                        member_name=member['name'],
                        role=member.get('role', 'Team Member'),
                        avatar=member.get('avatar')
                    )
                    db.session.add(team_member)
                    print(f"Added team member: {member['name']} with role: {member.get('role', 'Team Member')}")
                elif isinstance(member, str):
                    team_member = ProjectTeamMember(
                        project_id=new_project.id,
                        member_name=member
                    )
                    db.session.add(team_member)
                    print(f"Added team member with name string: {member}")
        else:
            print("No team members provided in data or not a list")
        
        # Add current user as a team member if not already included
        current_user_in_team = False
        for member in new_project.team_members:
            if member.member_name == current_user.name:
                current_user_in_team = True
                print(f"User {current_user.name} already in team")
                break
        
        if not current_user_in_team:
            owner_member = ProjectTeamMember(
                project_id=new_project.id,
                member_name=current_user.name,
                role='Project Owner'
            )
            db.session.add(owner_member)
            print(f"Added current user {current_user.name} as Project Owner")
        
        db.session.commit()
        print("Project saved successfully with all team members")
        
        # Return the full project data including team members
        project_data = new_project.to_dict()
        print(f"Returning project data with {len(project_data['teamMembers'])} team members")
        
        return jsonify({
            'success': True, 
            'message': 'Project created successfully',
            'project': project_data
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating project: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/projects', methods=['GET'])
def get_projects():
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get all projects owned by the current user
        owned_projects = Project.query.filter_by(user_id=current_user.id).all()
        
        # Get all projects where the current user is a team member
        team_member_projects_ids = db.session.query(Project.id)\
            .join(ProjectTeamMember, Project.id == ProjectTeamMember.project_id)\
            .filter(ProjectTeamMember.member_name == current_user.name)\
            .filter(Project.user_id != current_user.id)\
            .all()
        
        team_member_projects = []
        for project_id in team_member_projects_ids:
            project = Project.query.get(project_id[0])
            if project:
                team_member_projects.append(project)
        
        # Combine both sets of projects
        all_projects = owned_projects + team_member_projects
        
        return jsonify({
            'success': True,
            'projects': [project.to_dict() for project in all_projects]
        }), 200
        
    except Exception as e:
        print(f"Error getting projects: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/projects/<int:project_id>', methods=['GET'])
def get_project(project_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get the project
        project = Project.query.get(project_id)
        
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        
        # Check if user is the owner
        is_owner = project.user_id == current_user.id
        
        # If not owner, check if user is a team member
        is_team_member = False
        if not is_owner:
            team_member = ProjectTeamMember.query.filter_by(
                project_id=project_id, 
                member_name=current_user.name
            ).first()
            is_team_member = team_member is not None
        
        # Only allow access if user is owner or team member
        if not (is_owner or is_team_member):
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'project': project.to_dict(),
            'is_owner': is_owner
        }), 200
        
    except Exception as e:
        print(f"Error getting project details: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/projects/<int:project_id>', methods=['PUT'])
def update_project(project_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    data = request.get_json()
    
    try:
        # Get the project
        project = Project.query.filter_by(id=project_id, user_id=current_user.id).first()
        
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        
        # Update project fields
        if 'name' in data:
            project.name = data['name']
        if 'description' in data:
            project.description = data['description']
        if 'startDate' in data:
            project.start_date = datetime.fromisoformat(data['startDate']).date()
        if 'endDate' in data:
            project.end_date = datetime.fromisoformat(data['endDate']).date()
        if 'priority' in data:
            project.priority = data['priority']
        if 'progress' in data:
            project.progress = data['progress']
        
        # Update team members if provided
        if 'teamMembers' in data:
            # Remove existing team members
            ProjectTeamMember.query.filter_by(project_id=project.id).delete()
            
            # Add new team members
            for member in data['teamMembers']:
                if isinstance(member, dict) and 'name' in member:
                    team_member = ProjectTeamMember(
                        project_id=project.id,
                        member_name=member['name'],
                        role=member.get('role', 'Team Member'),
                        avatar=member.get('avatar')
                    )
                    db.session.add(team_member)
                elif isinstance(member, str):
                    team_member = ProjectTeamMember(
                        project_id=project.id,
                        member_name=member
                    )
                    db.session.add(team_member)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Project updated successfully',
            'project': project.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get the project
        project = Project.query.filter_by(id=project_id, user_id=current_user.id).first()
        
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        
        # Delete the project (will cascade delete team members due to relationship)
        db.session.delete(project)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Project deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Task API Routes
@app.route('/api/projects/<int:project_id>/tasks', methods=['POST'])
def create_task(project_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    data = request.get_json()
    
    # Validate input
    required_fields = ['title', 'dueDate', 'priority']
    for field in required_fields:
        if field not in data:
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    try:
        # Get the project
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
            
        # Check if current user is owner
        is_owner = project.user_id == current_user.id
        
        # If not owner, check if user is a team member
        is_team_member = False
        if not is_owner:
            team_member = ProjectTeamMember.query.filter_by(
                project_id=project_id, 
                member_name=current_user.name
            ).first()
            is_team_member = team_member is not None
        
        # Only allow access if user is owner or team member
        if not (is_owner or is_team_member):
            return jsonify({'success': False, 'message': 'Access denied: You are not a member of this project'}), 403
        
        print(f"Creating task for project {project_id} by user {current_user.name} (owner: {is_owner}, team member: {is_team_member})")
        
        # Create new task
        new_task = Task(
            title=data['title'],
            description=data.get('description', ''),
            priority=data['priority'],
            due_date=datetime.fromisoformat(data['dueDate']).date(),
            project_id=project_id,
            assignee=data.get('assignee')
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        # Recalculate project progress
        update_project_progress(project_id)
        
        return jsonify({
            'success': True, 
            'message': 'Task created successfully',
            'task': new_task.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating task: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/projects/<int:project_id>/tasks', methods=['GET'])
def get_tasks(project_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get the project
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
            
        # Check if current user is owner
        is_owner = project.user_id == current_user.id
        
        # If not owner, check if user is a team member
        is_team_member = False
        if not is_owner:
            team_member = ProjectTeamMember.query.filter_by(
                project_id=project_id, 
                member_name=current_user.name
            ).first()
            is_team_member = team_member is not None
        
        # Only allow access if user is owner or team member
        if not (is_owner or is_team_member):
            return jsonify({'success': False, 'message': 'Access denied: You are not a member of this project'}), 403
        
        # Get tasks for the project
        tasks = Task.query.filter_by(project_id=project_id).all()
        
        return jsonify({
            'success': True,
            'tasks': [task.to_dict() for task in tasks]
        }), 200
        
    except Exception as e:
        print(f"Error getting tasks: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    data = request.get_json()
    
    try:
        # Get the task
        task = Task.query.filter_by(id=task_id).first()
        
        if not task:
            return jsonify({'success': False, 'message': 'Task not found'}), 404
        
        # Check if the task belongs to a project owned by the user
        project = Project.query.filter_by(id=task.project_id, user_id=current_user.id).first()
        if not project:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Update task fields
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'priority' in data:
            task.priority = data['priority']
        if 'dueDate' in data:
            task.due_date = datetime.fromisoformat(data['dueDate']).date()
        if 'completed' in data:
            task.completed = data['completed']
        if 'assignee' in data:
            task.assignee = data['assignee']
        
        db.session.commit()
        
        # Recalculate project progress
        update_project_progress(task.project_id)
        
        return jsonify({
            'success': True,
            'message': 'Task updated successfully',
            'task': task.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get the task
        task = Task.query.filter_by(id=task_id).first()
        
        if not task:
            return jsonify({'success': False, 'message': 'Task not found'}), 404
        
        # Check if the task belongs to a project owned by the user
        project = Project.query.filter_by(id=task.project_id, user_id=current_user.id).first()
        if not project:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Save project_id for updating progress later
        project_id = task.project_id
        
        # Delete the task
        db.session.delete(task)
        db.session.commit()
        
        # Recalculate project progress
        update_project_progress(project_id)
        
        return jsonify({
            'success': True,
            'message': 'Task deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Helper function to update project progress based on task completion
def update_project_progress(project_id):
    project = Project.query.get(project_id)
    if not project:
        return
    
    tasks = Task.query.filter_by(project_id=project_id).all()
    
    if not tasks:
        project.progress = 0
    else:
        completed_tasks = sum(1 for task in tasks if task.completed)
        project.progress = int((completed_tasks / len(tasks)) * 100)
    
    db.session.commit()

# Serve other static files
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('../', filename)

# Add this new endpoint for testing
@app.route('/api/mock/project/<int:project_id>', methods=['GET'])
def mock_project(project_id):
    # Return a mock project for testing purposes
    mock_data = {
        'success': True,
        'project': {
            'id': project_id,
            'name': f'Test Project {project_id}',
            'description': 'This is a test project for development purposes.',
            'startDate': '2023-01-01',
            'endDate': '2023-12-31',
            'priority': 'High',
            'progress': 45,
            'objectives': [
                'Complete frontend implementation',
                'Set up database models',
                'Implement authentication',
                'Create API endpoints'
            ],
            'teamMembers': [
                {'id': 1, 'name': 'John Doe', 'role': 'Project Manager', 'avatar': None},
                {'id': 2, 'name': 'Jane Smith', 'role': 'Developer', 'avatar': None},
                {'id': 3, 'name': 'Bob Johnson', 'role': 'Designer', 'avatar': None}
            ],
            'tasks': [
                {
                    'id': 1,
                    'title': 'Design UI mockups',
                    'description': 'Create wireframes and mockups for all pages',
                    'priority': 'Medium',
                    'dueDate': '2023-03-15',
                    'completed': True,
                    'assignee': 'Bob Johnson'
                },
                {
                    'id': 2,
                    'title': 'Implement login page',
                    'description': 'Create the login page with authentication',
                    'priority': 'High',
                    'dueDate': '2023-04-01',
                    'completed': False,
                    'assignee': 'Jane Smith'
                },
                {
                    'id': 3,
                    'title': 'Set up database',
                    'description': 'Configure and initialize the database',
                    'priority': 'High',
                    'dueDate': '2023-03-20',
                    'completed': False,
                    'assignee': 'John Doe'
                }
            ]
        }
    }
    return jsonify(mock_data)

# Add this route to check token validity (already in your file but might need updating)
@app.route('/api/check-token', methods=['GET'])
def check_token():
    """Endpoint to check token validity - supports both JWT-Extended and legacy tokens"""
    print("Token check request received")
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            'success': False, 
            'message': 'Token is missing or improperly formatted'
        }), 401
    
    token = auth_header.split(' ')[1]
    
    # Try dual authentication approach
    
    # First try Flask-JWT-Extended
    from flask_jwt_extended import decode_token, get_jwt_identity
    try:
        # This will verify the token with Flask-JWT-Extended
        decode_token(token)
        # If we get here, it's a valid JWT-Extended token
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'success': False, 
                'message': f'User not found for ID: {user_id}'
            }), 401
            
        print(f"JWT-Extended token validated for user: {user.name}")
        return jsonify({
            'success': True, 
            'message': 'Token is valid (JWT-Extended)', 
            'user': user.to_dict(),
            'token_type': 'jwt_extended'
        })
    except Exception as jwt_ext_error:
        print(f"JWT-Extended validation failed: {str(jwt_ext_error)}")
        
        # If JWT-Extended failed, try legacy token validation
        try:
            # Legacy token validation
            data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data.get('user_id')
            
            if not user_id:
                return jsonify({
                    'success': False, 
                    'message': 'Invalid token format - missing user_id'
                }), 401
                
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({
                    'success': False, 
                    'message': f'User not found for ID: {user_id}'
                }), 401
                
            print(f"Legacy token validated for user: {user.name}")
            return jsonify({
                'success': True, 
                'message': 'Token is valid (Legacy)', 
                'user': user.to_dict(),
                'token_type': 'legacy'
            })
        except Exception as pyjwt_error:
            print(f"Legacy token validation also failed: {str(pyjwt_error)}")
            return jsonify({
                'success': False, 
                'message': 'Invalid token - failed both validation methods',
                'jwt_extended_error': str(jwt_ext_error),
                'legacy_error': str(pyjwt_error)
            }), 401

# Add a debug endpoint to check database contents
@app.route('/api/debug/database', methods=['GET'])
def debug_database():
    try:
        # Get all users
        users = User.query.all()
        user_data = [user.to_dict() for user in users]
        
        # Get all projects with their associated data
        projects = Project.query.all()
        project_data = []
        
        for project in projects:
            # Get the raw objectives string from database
            raw_objectives = project.objectives
            
            # Parse objectives if it exists
            objectives_list = []
            if raw_objectives:
                import json
                try:
                    objectives_list = json.loads(raw_objectives)
                except Exception as e:
                    # If it's not valid JSON, try to parse as comma-separated
                    if isinstance(raw_objectives, str):
                        if ',' in raw_objectives:
                            objectives_list = [obj.strip() for obj in raw_objectives.split(',')]
                        else:
                            objectives_list = [raw_objectives]
            
            # Get team members
            team_members = ProjectTeamMember.query.filter_by(project_id=project.id).all()
            team_data = [member.to_dict() for member in team_members]
            
            # Get tasks
            tasks = Task.query.filter_by(project_id=project.id).all()
            task_data = [task.to_dict() for task in tasks]
            
            project_data.append({
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date.isoformat() if project.start_date else None,
                'end_date': project.end_date.isoformat() if project.end_date else None,
                'priority': project.priority,
                'progress': project.progress,
                'user_id': project.user_id,
                'raw_objectives': raw_objectives,
                'parsed_objectives': objectives_list,
                'team_members': team_data,
                'tasks': task_data
            })
        
        return jsonify({
            'success': True,
            'users': user_data,
            'projects': project_data
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Add this new endpoint to reset project progress
@app.route('/api/debug/reset-progress', methods=['POST'])
def reset_project_progress():
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get all projects
        projects = Project.query.all()
        reset_count = 0
        
        for project in projects:
            tasks = Task.query.filter_by(project_id=project.id).all()
            
            if not tasks and project.progress > 0:
                # Reset progress for projects without tasks
                old_progress = project.progress
                project.progress = 0
                reset_count += 1
                print(f"Reset progress for project {project.id} from {old_progress}% to 0%")
            
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Reset progress for {reset_count} projects',
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting progress: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/debug/add-sample-tasks', methods=['POST'])
def add_sample_tasks_endpoint():
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Get project id from request
        data = request.get_json()
        if not data or 'project_id' not in data:
            return jsonify({'success': False, 'message': 'Project ID is required'}), 400
        
        project_id = data['project_id']
        project = Project.query.get(project_id)
        
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        
        # Check if user is owner
        is_owner = project.user_id == current_user.id
        if not is_owner:
            return jsonify({'success': False, 'message': 'Only the project owner can add sample tasks'}), 403
        
        # Create sample tasks
        tasks_created = create_sample_tasks(project)
        
        return jsonify({
            'success': True,
            'message': f'Created {tasks_created} sample tasks for project {project_id}',
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating sample tasks: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Helper function to create sample tasks for a project
def create_sample_tasks(project):
    try:
        task_count = 0
        
        # Create sample tasks based on project objectives
        objectives = []
        if project.objectives:
            import json
            try:
                objectives = json.loads(project.objectives)
            except:
                if isinstance(project.objectives, str):
                    objectives = [obj.strip() for obj in project.objectives.split(',')]
        
        # If no objectives, create generic tasks
        if not objectives:
            objectives = [
                "Research and planning", 
                "Implementation", 
                "Testing and quality assurance"
            ]
        
        # Get team members for the project
        team_members = ProjectTeamMember.query.filter_by(project_id=project.id).all()
        member_names = [member.member_name for member in team_members]
        
        # Create at least 3 tasks
        for i, objective in enumerate(objectives[:3]):
            # Create task based on objective
            due_date = project.end_date - timedelta(days=(len(objectives) - i) * 7)
            
            # Assign to team member if available
            assignee = None
            if member_names and i < len(member_names):
                assignee = member_names[i]
            
            # Set priority based on index
            priorities = ["High", "Medium", "Low"]
            priority = priorities[i % len(priorities)]
            
            # Create task
            task = Task(
                title=f"Task: {objective}",
                description=f"Complete the {objective.lower()} phase of the project",
                priority=priority,
                due_date=due_date,
                project_id=project.id,
                assignee=assignee,
                completed=(i == 0)  # Make first task completed
            )
            
            db.session.add(task)
            task_count += 1
        
        # Update project progress
        update_project_progress(project.id)
        db.session.commit()
        
        return task_count
    except Exception as e:
        db.session.rollback()
        print(f"Error creating sample tasks: {str(e)}")
        return 0

# Add this new endpoint to sync all project progress values
@app.route('/api/debug/sync-progress', methods=['POST'])
def sync_progress_endpoint():
    # Verify token
    current_user, error_response, error_code = verify_token()
    if error_response:
        return jsonify(error_response), error_code
    
    try:
        # Synchronize all project progress values
        projects = Project.query.all()
        updated_count = 0
        
        for project in projects:
            tasks = Task.query.filter_by(project_id=project.id).all()
            
            # Set progress based on task completion
            old_progress = project.progress
            if not tasks:
                # If no tasks, progress should be 0
                project.progress = 0
            else:
                completed_tasks = sum(1 for task in tasks if task.completed)
                project.progress = int((completed_tasks / len(tasks)) * 100)
            
            # Only count as updated if progress value changed
            if old_progress != project.progress:
                updated_count += 1
                print(f"Updated project {project.id} progress: {old_progress}% → {project.progress}%")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Synchronized progress for {updated_count} projects',
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error synchronizing progress: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Add these routes for chat functionality
@app.route('/api/chat/messages/<int:project_id>', methods=['GET'])
@jwt_required()
def get_chat_messages(project_id):
    """Get chat messages for a specific project"""
    # Verify project exists and user has access
    project = Project.query.get(project_id)
    if not project:
        return jsonify({'success': False, 'message': 'Project not found'}), 404
    
    # Check if user is a member of the project
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    # Check if user has access to this project
    user_has_access = False
    if project.user_id == current_user_id:
        user_has_access = True
    else:
        # Check if user is in team members
        for member in project.team_members:
            if user.name == member.member_name:
                user_has_access = True
                break
    
    if not user_has_access:
        return jsonify({'success': False, 'message': 'You do not have access to this project'}), 403
    
    # Get messages ordered by timestamp (most recent 50)
    messages = ChatMessage.query.filter_by(project_id=project_id).order_by(ChatMessage.timestamp).limit(50).all()
    
    # Format messages
    formatted_messages = []
    for message in messages:
        sender = User.query.get(message.user_id)
        formatted_messages.append({
            'id': message.id,
            'sender_id': message.user_id,
            'sender_name': sender.name if sender else 'Unknown User',
            'content': message.content,
            'timestamp': message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'type': message.message_type,
            'encrypted': message.encrypted  # Include the encrypted flag in the response
        })
    
    return jsonify({'success': True, 'messages': formatted_messages})

@app.route('/api/chat/messages/<int:project_id>', methods=['POST'])
@jwt_required()
def save_chat_message(project_id):
    """Save a chat message for a specific project"""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    content = data.get('content')
    message_type = data.get('type', 'message')
    encrypted = data.get('encrypted', False)  # Check if message is encrypted
    
    if not content:
        return jsonify({'success': False, 'message': 'Message content is required'}), 400
    
    # Verify project exists and user has access
    project = Project.query.get(project_id)
    if not project:
        return jsonify({'success': False, 'message': 'Project not found'}), 404
    
    # Get current user
    current_user_id = get_jwt_identity()
    
    # Create and save the message
    new_message = ChatMessage(
        project_id=project_id,
        user_id=current_user_id,
        content=content,
        message_type=message_type,
        encrypted=encrypted,  # Store the encrypted flag
        timestamp=datetime.utcnow()
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    # Return the saved message
    sender = User.query.get(current_user_id)
    formatted_message = {
        'id': new_message.id,
        'sender_id': new_message.user_id,
        'sender_name': sender.name if sender else 'Unknown User',
        'content': new_message.content,
        'timestamp': new_message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'type': new_message.message_type,
        'encrypted': new_message.encrypted  # Include encrypted flag in response
    }
    
    return jsonify({'success': True, 'message': formatted_message})

# Custom combined auth decorator
def dual_auth_required(fn):
    """Decorator that supports both legacy JWT and Flask-JWT-Extended tokens"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # First, try to verify with legacy token method
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
            try:
                # Try to decode with PyJWT first
                decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded.get('user_id')
                
                if user_id:
                    print(f"Dual auth: Valid legacy token for user {user_id}")
                    # Store user_id in g for access in the endpoint
                    g.user_id = user_id
                    return fn(*args, **kwargs)
            except Exception as e:
                # Not a valid legacy token, will try Flask-JWT-Extended next
                print(f"Legacy token validation failed: {str(e)}")
                # Continue to Flask-JWT-Extended
        
        # If we got here, legacy token didn't work, try Flask-JWT-Extended
        jwt_decorator = jwt_required()
        try:
            return jwt_decorator(fn)(*args, **kwargs)
        except Exception as e:
            # If Flask-JWT-Extended validation also fails, return appropriate error
            print(f"Flask-JWT-Extended validation failed: {str(e)}")
            traceback.print_exc()
            return jsonify({'error': 'Authentication failed'}), 401
    
    return wrapper

# Function to get user ID for dual auth
def get_dual_auth_identity():
    """Get user ID from either legacy token or Flask-JWT-Extended token"""
    # Check if legacy auth was used
    if hasattr(g, 'user_id'):
        return g.user_id
    
    # Otherwise use Flask-JWT-Extended
    return get_jwt_identity()

# Replace @jwt_required() with @dual_auth_required
@app.route('/api/projects/<int:project_id>/documents', methods=['GET'])
@dual_auth_required
def get_project_documents(project_id):
    try:
        # Debug JWT information from the request context
        print("----- DOCUMENT ENDPOINT DEBUG -----")
        print(f"Request endpoint: {request.endpoint}")
        
        # Get user ID from either legacy or JWT-Extended token
        current_user_id = get_dual_auth_identity()
        print(f"Authenticated user ID: {current_user_id}")
        
        # Verify user has access to project
        project = Project.query.get_or_404(project_id)
        print(f"Found project {project_id}, owned by user {project.user_id}")
        
        # Check if user is project owner or a team member
        if project.user_id == current_user_id:
            # User is project owner
            user_has_access = True
            print(f"User {current_user_id} is the project owner - access granted")
        else:
            # Get current user
            current_user = User.query.get(current_user_id)
            if not current_user:
                print(f"User {current_user_id} not found in database")
                return jsonify({'error': 'User not found'}), 404
                
            # Check if user's name is in the project team members
            team_member_names = [member.member_name for member in project.team_members]
            print(f"Project team members: {team_member_names}")
            print(f"Current user name: {current_user.name}")
            
            user_has_access = current_user.name in team_member_names
            print(f"Is user a team member? {user_has_access}")
            
        if not user_has_access:
            print(f"Access denied for user {current_user_id} to project {project_id}")
            return jsonify({'error': 'Access denied'}), 403
            
        documents = Document.query.filter_by(project_id=project_id).all()
        print(f"Found {len(documents)} documents for project {project_id}")
        return jsonify([doc.to_dict() for doc in documents])
    except Exception as e:
        import traceback
        print(f"Error in document endpoint: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects/<int:project_id>/documents', methods=['POST'])
@dual_auth_required
def upload_document(project_id):
    try:
        # Get user ID from either legacy or JWT-Extended token
        current_user_id = get_dual_auth_identity()
        print(f"Upload document: Authenticated user ID: {current_user_id}")
        
        # Verify user has access to project
        project = Project.query.get_or_404(project_id)
        
        # Check if user is project owner or a team member
        if project.user_id == current_user_id:
            # User is project owner
            user_has_access = True
        else:
            # Get current user
            current_user = User.query.get(current_user_id)
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
                
            # Check if user's name is in the project team members
            user_has_access = any(member.member_name == current_user.name for member in project.team_members)
            
        if not user_has_access:
            return jsonify({'error': 'Access denied'}), 403
            
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(app.root_path, 'static', 'uploads', str(project_id))
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
        file_path = os.path.join(upload_dir, unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Create document record
        document = Document(
            project_id=project_id,
            user_id=current_user_id,
            filename=filename,
            file_path=file_path,
            file_type=os.path.splitext(filename)[1][1:].lower(),
            description=request.form.get('description'),
            tags=request.form.get('tags')
        )
        
        db.session.add(document)
        db.session.commit()
        
        return jsonify(document.to_dict())
    except Exception as e:
        import traceback
        print(f"Error in upload document: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<int:document_id>', methods=['GET'])
@dual_auth_required
def download_document(document_id):
    try:
        document = Document.query.get_or_404(document_id)
        
        # Get user ID from either legacy or JWT-Extended token
        current_user_id = get_dual_auth_identity()
        print(f"Download document: Authenticated user ID: {current_user_id}")
        
        # Get the related project
        project = Project.query.get(document.project_id)
        if not project:
            return jsonify({'error': 'Project not found'}), 404
            
        # Check if user is project owner or a team member
        if project.user_id == current_user_id:
            # User is project owner
            user_has_access = True
        else:
            # Get current user
            current_user = User.query.get(current_user_id)
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
                
            # Check if user's name is in the project team members
            user_has_access = any(member.member_name == current_user.name for member in project.team_members)
            
        if not user_has_access:
            return jsonify({'error': 'Access denied'}), 403
            
        return send_file(
            document.file_path,
            as_attachment=True,
            download_name=document.filename
        )
    except Exception as e:
        import traceback
        print(f"Error in download document: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    return jsonify({'status': 'ok', 'message': 'API is working'})

@app.route('/api/debug/token', methods=['GET'])
def debug_token():
    auth_header = request.headers.get('Authorization', '')
    print(f"Received Authorization header: {auth_header}")
    
    if not auth_header:
        return jsonify({
            'status': 'error',
            'message': 'No Authorization header found',
            'headers_received': {k: v for k, v in request.headers.items()}
        }), 401
    
    # Check if it starts with 'Bearer '
    if not auth_header.startswith('Bearer '):
        return jsonify({
            'status': 'error',
            'message': 'Authorization header must start with Bearer',
            'header_received': auth_header
        }), 401
    
    # Extract the token
    token = auth_header.split(' ')[1]
    
    if not token:
        return jsonify({
            'status': 'error',
            'message': 'No token found in Authorization header',
            'header_received': auth_header
        }), 401
    
    # Try to decode the token
    try:
        import jwt
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({
            'status': 'success',
            'message': 'Token is valid',
            'decoded': decoded
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Token validation error: {str(e)}',
            'token_received': token[:10] + '...' if len(token) > 10 else token
        }), 401

@app.route('/api/debug/jwt-test', methods=['GET'])
def debug_jwt_test():
    """Debug endpoint to test both JWT implementations"""
    auth_header = request.headers.get('Authorization', '')
    print(f"JWT test: Received Authorization header: {auth_header[:30]}...")
    
    if not auth_header:
        return jsonify({
            'status': 'error',
            'message': 'No Authorization header found',
            'headers_received': {k: v for k, v in request.headers.items()}
        }), 401
    
    # Check if it starts with 'Bearer '
    if not auth_header.startswith('Bearer '):
        return jsonify({
            'status': 'error',
            'message': 'Authorization header must start with Bearer',
            'header_received': auth_header
        }), 401
    
    # Extract the token
    token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else ''
    
    if not token:
        return jsonify({
            'status': 'error',
            'message': 'No token found in Authorization header',
            'header_received': auth_header
        }), 401
    
    response_data = {
        'token_length': len(token),
        'token_preview': token[:20] + '...',
        'pyjwt_result': None,
        'flask_jwt_result': None,
    }
    
    # Try to decode with pyjwt
    try:
        decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        response_data['pyjwt_result'] = {
            'status': 'success',
            'decoded': decoded
        }
        
        # Check if we have user_id instead of sub (legacy token)
        if 'user_id' in decoded and 'sub' not in decoded:
            response_data['pyjwt_result']['token_type'] = 'Legacy token (user_id without sub)'
            response_data['pyjwt_result']['middleware_compatible'] = True
        elif 'sub' in decoded:
            response_data['pyjwt_result']['token_type'] = 'JWT Extended token (has sub field)'
            response_data['pyjwt_result']['middleware_compatible'] = False
        else:
            response_data['pyjwt_result']['token_type'] = 'Unknown format (no user_id or sub)'
            response_data['pyjwt_result']['middleware_compatible'] = False
            
    except Exception as e:
        response_data['pyjwt_result'] = {
            'status': 'error',
            'message': f'Error: {str(e)}'
        }
    
    # Try to validate with Flask-JWT-Extended
    from flask_jwt_extended import decode_token
    try:
        flask_decoded = decode_token(token)
        response_data['flask_jwt_result'] = {
            'status': 'success',
            'decoded': flask_decoded
        }
    except Exception as e:
        response_data['flask_jwt_result'] = {
            'status': 'error',
            'message': f'Error: {str(e)}'
        }
    
    # Overall result
    if response_data['pyjwt_result']['status'] == 'success' or response_data['flask_jwt_result']['status'] == 'success':
        response_data['overall'] = 'Token is valid in at least one system'
        
        # Check if middleware would help
        if (response_data['pyjwt_result']['status'] == 'success' and 
            response_data['flask_jwt_result']['status'] == 'error' and
            'user_id' in decoded):
            response_data['middleware_note'] = 'Our middleware should make this token work with flask-jwt-extended'
            
        return jsonify(response_data)
    else:
        response_data['overall'] = 'Token is invalid in both systems'
        return jsonify(response_data), 401

@app.route('/api/test/documents/<int:project_id>', methods=['GET'])
def test_get_project_documents(project_id):
    """Test endpoint for document access using manual token validation"""
    try:
        # Get the token and verify using manual method (like in verify_token)
        auth_header = request.headers.get('Authorization', '')
        print(f"Test Documents: Received auth header: {auth_header[:30]}...")
        
        if not auth_header:
            return jsonify({'error': 'No Authorization header provided'}), 401
            
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization header must start with Bearer'}), 401
            
        # Extract the token
        token = auth_header.split(' ')[1]
        
        try:
            # Use pyjwt for decoding
            decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(f"Test Documents: Decoded token: {decoded}")
            
            # Get user from token
            user_id = decoded.get('user_id')
            if not user_id:
                return jsonify({'error': 'Invalid token - no user_id'}), 401
                
            current_user = User.query.get(user_id)
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
                
            print(f"Test Documents: Authenticated user: {current_user.name} (ID: {current_user.id})")
                
            # Now get the project and documents
            project = Project.query.get_or_404(project_id)
            print(f"Test Documents: Found project {project_id}, owned by user {project.user_id}")
            
            # Check if user is project owner or a team member
            if project.user_id == current_user.id:
                # User is project owner
                user_has_access = True
                print(f"Test Documents: User {current_user.id} is the project owner")
            else:
                # Check if user's name is in the project team members
                team_member_names = [member.member_name for member in project.team_members]
                print(f"Test Documents: Project team members: {team_member_names}")
                print(f"Test Documents: Current user name: {current_user.name}")
                
                user_has_access = current_user.name in team_member_names
                print(f"Test Documents: User access granted: {user_has_access}")
                
            if not user_has_access:
                print(f"Test Documents: Access denied for user {current_user.id} to project {project_id}")
                return jsonify({'error': 'Access denied'}), 403
                
            documents = Document.query.filter_by(project_id=project_id).all()
            print(f"Test Documents: Found {len(documents)} documents for project {project_id}")
            return jsonify({
                'success': True,
                'message': 'Access granted using manual verification',
                'documents': [doc.to_dict() for doc in documents]
            })
            
        except Exception as e:
            print(f"Test Documents: Token validation error: {str(e)}")
            return jsonify({'error': f'Token validation error: {str(e)}'}), 401
            
    except Exception as e:
        import traceback
        print(f"Test Documents: Error in endpoint: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/check-token-type', methods=['GET'])
def check_token_type():
    """Endpoint to check what type of token is being used"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            'valid': False,
            'message': 'Missing or improperly formatted token',
            'token_type': 'unknown'
        }), 401
        
    token = auth_header.split(' ')[1]
    
    # Check token format
    token_info = {
        'valid': False,
        'token_type': 'unknown',
        'token_length': len(token),
        'parts': len(token.split('.')),
        'is_jwt_format': len(token.split('.')) == 3
    }
    
    # Try with PyJWT
    try:
        decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Determine token type
        if 'user_id' in decoded and 'sub' not in decoded:
            token_info['token_type'] = 'legacy_jwt'
            token_info['valid'] = True
            token_info['identity'] = decoded['user_id']
            token_info['message'] = 'Valid legacy JWT token'
            token_info['auth_method'] = 'Use legacy or dual authentication'
        elif 'sub' in decoded:
            token_info['token_type'] = 'jwt_extended'
            token_info['valid'] = True
            token_info['identity'] = decoded['sub']
            token_info['message'] = 'Valid Flask-JWT-Extended token'
            token_info['auth_method'] = 'Use JWT Extended authentication'
        else:
            token_info['message'] = 'JWT format but missing identity fields'
    except Exception as e:
        token_info['pyjwt_error'] = str(e)
    
    # Try with Flask-JWT-Extended
    try:
        from flask_jwt_extended import decode_token
        flask_decoded = decode_token(token)
        token_info['jwt_extended_valid'] = True
        token_info['jwt_extended_decode'] = {k: v for k, v in flask_decoded.items() if k in ['identity', 'type', 'fresh']}
        
        # If it passed JWT-Extended validation but we didn't already determine type
        if token_info['token_type'] == 'unknown':
            token_info['token_type'] = 'jwt_extended'
            token_info['valid'] = True
            token_info['identity'] = flask_decoded['sub']
            token_info['message'] = 'Valid Flask-JWT-Extended token (passed decode_token)'
            token_info['auth_method'] = 'Use JWT Extended authentication'
    except Exception as e:
        token_info['jwt_extended_error'] = str(e)
    
    if not token_info['valid']:
        # If we get here, neither method could validate the token
        token_info['message'] = 'Invalid token - not recognized by any method'
        return jsonify(token_info), 401
        
    return jsonify(token_info)

@app.route('/api/check-certificate', methods=['GET'])
def check_certificate():
    """
    Endpoint that allows the client to verify the server's certificate.
    The actual certificate validation happens at the TLS layer before this
    endpoint is even called. If the certificate is invalid, the request
    would not reach this endpoint at all unless the client ignored the
    certificate errors.
    """
    return jsonify({
        'success': True,
        'message': 'Certificate validation successful',
        'secure': request.is_secure,
        'protocol': request.scheme
    }), 200

# Modified run method to use SSL if enabled
if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 5001))  # Changed from 5000 to 5001
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    
    ssl_context = None
    if app.config.get('SSL_ENABLED', False):
        # Check if SSL certificate files exist
        cert_path = app.config['SSL_CERT_PATH']
        key_path = app.config['SSL_KEY_PATH']
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"SSL certificates found at {cert_path} and {key_path}")
            
            # Create an SSL context with more secure settings
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            # Disable outdated and insecure protocols (TLS 1.0 and 1.1)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            # Use only strong cipher suites
            context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
            
            ssl_context = context
            print("HTTPS enabled with TLS 1.2+ and strong cipher suites")
        else:
            print(f"Warning: SSL certificates not found at {cert_path} and/or {key_path}")
            print("Server will run without HTTPS")
    
    print(f"Starting server on {host}:{port} {'with HTTPS' if ssl_context else 'without HTTPS'}")
    app.run(debug=True, host=host, port=port, ssl_context=ssl_context) 