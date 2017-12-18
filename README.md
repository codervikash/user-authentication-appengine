# user-authentication-appengine

An inplementation of user authentication and management on Google App Engine. IT has featues to login, logout, reset password, session management. Sending mail for signup and reset is also implemented.

It can be plugged to any app running on Google App Engine to hhave user login and management. Check installation for it.

## Usage/Installation:
1. Clone the repo `git clone https://github.com/codervikash/user-authentication-appengine.git`.
2. Add email id in `config` in `main.py`.
3. Run application by `dev_appserver.py app.yaml`.
4. To deploy, `gcloud app deploy  app.yaml --project <project_name>`.

## Detail/Documentation:
Checkout my blog for understading how it works: [link](https://blog.vikash.me/app-engine-user-authentication/)

## Licence:
MIT

