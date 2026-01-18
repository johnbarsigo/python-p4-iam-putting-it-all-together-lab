from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user', lazy=True)

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hash is not accessible.")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)
    
    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == '':
            raise ValueError("Username must be present.")
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != self.id:
            raise ValueError("Username must be unique.")
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == '':
            raise ValueError("Title must be present.")
        return title
    
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or instructions.strip() == '':
            raise ValueError("Instructions must be present.")
        if len(instructions.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions