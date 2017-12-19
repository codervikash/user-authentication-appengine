from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
from google.appengine.api import mail

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)


class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')

    if not password or password != self.request.get('confirm_password'):
      params = {
        'message' : 'Password dont match'
      }
      self.render_template('signup.html',params)
    else:
      unique_properties = ['email_address']
      user_data = self.user_model.create_user(user_name,
        unique_properties,
        email_address=email, name=name, password_raw=password,
        last_name=last_name, verified=False)
      if not user_data[0]: #user_data is a tuple
        message = 'Username/email already exists. please login or choose different username/email.'

        params = {
          'message' : message
        }
        self.render_template('signup.html',params)
        return

      user = user_data[1]
      user_id = user.get_id()

      token = self.user_model.create_signup_token(user_id)

      verification_url = self.uri_for('verification', type='v', user_id=user_id,
        signup_token=token, _full=True)

      email_id = email

      mail.send_mail(sender= config['config']['admin'],
                to=email_id,
                subject="Approve account",
                body="""
              Respected Sir/Mam,
              Your sign up details are as follows:
              Name : %s
              Email Id : %s
              If its authorised, Please click on link below.
               %s

               Else, please reply back to this mail with details.""" % (name, email, verification_url))

      message = 'Thanks for signing up. Please check your mail ccount!'

      params = {
        'message' : message
      }
      self.render_template('login.html',params)

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    email = self.request.get('email')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    mail.send_mail(sender = config['config']['admin'],
                to=email,
                subject="Password Change",
                body="""
              Respected Sir/Mam,
              You requested for changing your account password.
              If its you, Please click on link below.
               %s

               Else, please reply back to this mail with details.""" %  verification_url)

    message = 'Check mail to verify password change and login again.'

    params = {
      'message' : message
    }

    self.render_template('login.html',params)




  def _serve_page(self, not_found=False):
    params = {
      'not_found': not_found
    }
    self.render_template('forgot.html', params)


class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)

    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      params = {
        'message': 'User email address has been verified. Please login to access dashboard'
      }

      self.render_template('login.html', params)
      return

    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):
  def get(self):
    self.redirect('/')

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    self.auth.unset_session()

    params = {
      'message' : 'Password Updated ! Login with new password.'
    }
    self.render_template('login.html',params)



class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password,  remember=True,
        save_session=True)
      v = self.user_model.get_by_auth_id(username)
      if v.verified is False:
        self.auth.unset_session()
        message = 'Email ID not veridfied, Please check your mail'
        self._serve_page(message,True)
        return
      else:
        self.redirect(self.uri_for('authenticated'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      message = 'Invalid password'
      self._serve_page( message,True)

  def _serve_page(self, message= False, failed=False):
    username = self.request.get('username')
    auth = self.auth
    if not auth.get_user_by_session():
      params = {
        'username': username,
        'failed': failed,
        'message' : message
      }
      self.render_template('login.html', params)
    else:
      self.redirect(self.uri_for('authenticated'))

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('login'))


class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('dashboard.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name'],
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  },
  'config' : {
  'admin' : '<admin_email_id>'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', LoginHandler, name='login'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/dashboard', AuthenticatedHandler, name='authenticated')
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
