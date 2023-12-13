from flask import Flask, request, jsonify
import re
from flask_mail import Mail, Message
import random
import string
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api,reqparse
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'c725b514880143cba9d842cc1f49a978'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prtyushdb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False,name='uq_user_name')
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False,name='uq_user_email')  # Add this line
    department = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    password_reset_token = db.Column(db.String(32), nullable=True)
    


with app.app_context():
    db.create_all()


class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')  # Add this line
        department = data.get('department')
        phone_number = data.get('phone_number')
        city = data.get('city')

        if not username or not password or not email or not department or not phone_number or not city:
            return {'message': 'Missing required fields'}, 400

        # Add additional validation for email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return {'message': 'Invalid email format'}, 400
        
        if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
            
            return {'message': 'Invalid password format'}, 400
        
        

        if not re.match(r"^[789]\d{9}$", phone_number):
           
            return {'message': 'Invalid phone number format'}, 400

        if User.query.filter_by(username=username).first():
            return {'message': 'Username already taken'}, 400

        if User.query.filter_by(email=email).first():
            return {'message': 'Email already taken'}, 400

        new_user = User(
            username=username,
            password=password,
            email=email,  # Add this line
            department=department,
            phone_number=phone_number,
            city=city,
        )

        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 200


  

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username_or_email = data.get('username')
        password = data.get('password')

        # Check if the input is an email or username
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if user and user.password == password:
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200

        return {'message': 'Invalid Credentials'}, 400
    

class AllUsers(Resource):
    @jwt_required()
    def get(self):
        users = User.query.all()
        user_list = []

        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email':user.email,
                'department': user.department,
                'phone_number':user.phone_number,
                'city':user.city,
                

            }
            user_list.append(user_data)

        return {'users': user_list}, 200
    
class DeleteAllUsers(Resource):
    @jwt_required()
    def delete(self):
        # Delete all users from the database
        db.session.query(User).delete()
        db.session.commit()



class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        return {'message': f'hello user {current_user_id}'}, 200


class UpdateUserProfile(Resource):
    @jwt_required()
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='New department for the user')
        parser.add_argument('email', type=str, help='New department for the user')
        parser.add_argument('department', type=str, help='New department for the user')
        parser.add_argument('phone_number', type=str, help='New phone number for the user')
        parser.add_argument('city', type=str, help='New city for the user')
      

        args = parser.parse_args()

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return {'message': 'User not found'}, 404
        
        if args['username']:
            # Check if the new username is already taken
            if User.query.filter_by(username=args['username']).first():
                return {'message': 'Username already taken'}, 400
            user.username = args['username']

        if args['email']:
            # Check if the new email is already taken
            if User.query.filter_by(email=args['email']).first():
                return {'message': 'Email already taken'}, 400
            user.email = args['email']

       

        if args['department']:
            user.department = args['department']

        if args['phone_number']:
            if not re.match(r"^[789]\d{9}$", args['phone_number']):
                return {'message': 'Invalid phone number format'}, 400
            user.phone_number = args['phone_number']

        if args['city']:
            user.city = args['city']

      

        db.session.commit()

        return {'message': 'User profile updated successfully'}, 200


class PasswordReset(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        user = User.query.filter_by(username=username).first()

        if not user:
            return {'message': 'User not found'}, 404

        # Generate a random password reset token
        reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        user.password_reset_token = reset_token
        db.session.commit()

        return {'reset_token': reset_token}, 200
    

class PasswordResetConfirm(Resource):
    def post(self, reset_token):
        data = request.get_json()
        new_password = data['new_password']

        user = User.query.filter_by(password_reset_token=reset_token).first()

        if not user:
            return {'message': 'Invalid or expired reset token'}, 400

        # Reset the password and clear the reset token
        user.password = new_password
        user.password_reset_token = None
        db.session.commit()

        return {'message': 'Password reset successful'}, 200
    



api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ProtectedResource, '/secure')
api.add_resource(AllUsers, '/users')
api.add_resource(DeleteAllUsers, '/delete')
api.add_resource(UpdateUserProfile, '/update_profile')
api.add_resource(PasswordReset, '/reset')
api.add_resource(PasswordResetConfirm, '/reset/<string:reset_token>')
             
if __name__ == "__main__":
    app.run(debug=True)






