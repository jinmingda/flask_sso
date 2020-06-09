###############################
# Monolithic app authentication
###############################
import os
from urllib.parse import urlencode

from flask import Flask, jsonify, url_for, redirect, session
from flask_session import Session
import redis
from sqlalchemy import create_engine, Column, String, Integer, Boolean
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required,
    UserMixin,
)
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)

app.config["SECRET_KEY"] = "some-secret-string"
app.config["PERMANENT_SESSION_LIFETIME"] = 86400
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = redis.from_url("redis://localhost:6379")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./db.sqlite3"
app.config["AUTH0_CLIENT_ID"] = os.environ["AUTH0_CLIENT_ID"]
app.config["AUTH0_CLIENT_SECRET"] = os.environ["AUTH0_CLIENT_SECRET"]
app.config["AUTH0_API_BASE_URL"] = os.environ["AUTH0_API_BASE_URL"]
app.config["AUTH0_ACCESS_TOKEN_URL"] = os.environ["AUTH0_ACCESS_TOKEN_URL"]
app.config["AUTH0_AUTHORIZE_URL"] = os.environ["AUTH0_AUTHORIZE_URL"]

Session(app)

login_manager = LoginManager()
login_manager.init_app(app)

oauth = OAuth(app)
auth0 = oauth.register(
    "auth0",
    client_id=app.config["AUTH0_CLIENT_ID"],
    client_secret=app.config["AUTH0_CLIENT_SECRET"],
    api_base_url=app.config["AUTH0_API_BASE_URL"],
    access_token_url=app.config["AUTH0_ACCESS_TOKEN_URL"],
    authorize_url=app.config["AUTH0_AUTHORIZE_URL"],
    client_kwargs={"scope": "openid profile email"},
)

engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
db_session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, unique=True)
    email_verified = Column(Boolean)
    name = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    picture = Column(String, nullable=True)

    def __init__(
        self, email, name=None, nickname=None, email_verified=None, picture=None
    ):
        self.email = email
        self.email_verified = email_verified
        self.name = name
        self.nickname = nickname
        self.picture = picture


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        exclude = ("id", "email_verified")


user_schema = UserSchema()


@login_manager.user_loader
def load_user(user_id):
    user = db_session.query(User).filter(User.id == user_id).first()
    return user


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)

    #################
    # Universal login
    #################
    return auth0.authorize_redirect(redirect_uri=redirect_uri)

    ################
    # Embedded login
    ################
    # Lock.js uses Cross Origin Authentication. In some browsers this can be
    # unreliable if you do not set up a Custom Domain and host your app on
    # the same domain. It also requires waiting time to load the login form,
    # which is bad for user experience.
    ################
    # state = uuid.uuid4().hex
    # api_base_url = app.config["AUTH0_API_BASE_URL"].lstrip("https://")
    # auth0.save_authorize_data(request, redirect_uri=redirect_uri, state=state)
    # return f"""
    #     <html>
    #     <body>
    #         <div id="root" style="width: 320px; margin: 40px auto; padding: 10px; box-sizing: border-box;">
    #             embedded area
    #         </div>
    #         <script src="https://cdn.auth0.com/js/lock/11.14/lock.min.js"></script>
    #         <script>
    #             var lock = new Auth0Lock('{app.config["AUTH0_CLIENT_ID"]}', '{api_base_url}', {{
    #                 container: 'root',
    #                 auth: {{
    #                     redirectUrl: '{session["_auth0_authlib_redirect_uri_"]}',
    #                     responseType: 'code',
    #                     params: {{
    #                         scope: 'openid email profile',
    #                         state: '{session["_auth0_authlib_state_"]}'
    #                     }}
    #                 }}
    #             }});
    #             lock.show();
    #         </script>
    #     </body>
    #     </html>
    # """


@app.route("/callback")
def callback():
    auth0.authorize_access_token()
    resp = auth0.get("userinfo")
    userinfo = resp.json()

    email = userinfo["email"]
    picture = userinfo["picture"]

    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, picture=picture)
        db_session.add(user)
        db_session.commit()

    login_user(user)
    # set csrf token in cookies/session here
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    logout_user()
    ############
    # SSO logout
    ############
    params = {
        "returnTo": url_for("home", _external=True),
        "client_id": app.config["AUTH0_CLIENT_ID"],
    }
    return redirect(auth0.api_base_url + "/v2/logout?" + urlencode(params))


@app.route("/")
def home():
    return """
    <a href='/login'>Login</a>
    <br>
    <a href='/logout'>Logout</a>
    <br>
    <a href='/api'>API</a>
    """


@app.route("/api")
@login_required
def api():
    serialized = user_schema.dump(current_user)
    return jsonify(serialized)


if __name__ == "__main__":
    # Run `flask run` to start dev server
    # Run `python app.py` to init dev DB
    Base.metadata.create_all(engine)
