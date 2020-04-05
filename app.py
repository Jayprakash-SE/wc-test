from flask import Flask, redirect, render_template, \
	url_for, session, request, jsonify
import requests
import mwoauth
import os

app = Flask(
	__name__, 
	template_folder='build',
	static_folder='build/static'
)

app.config["SECRET_KEY"] = os.urandom(34)

# Load configuration
# export APP_SETTINGS = "config.production" for Production
app.config.from_object(os.environ['APP_SETTINGS'])

consumer_token = mwoauth.ConsumerToken(
    app.config["CONSUMER_KEY"],
    app.config["CONSUMER_SECRET"]
)
handshaker = mwoauth.Handshaker(app.config["OAUTH_MWURI"], consumer_token)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
	return render_template('index.html') 


# ------ API Part -----------
@app.route('/api/profile')
def api_profile():
    return jsonify( {
        "logged": get_current_user() is not None,
        "username": get_current_user()
    })


# ------ OAuth Part ---------
@app.route('/login')
def login():
    redirect_to, request_token = handshaker.initiate()
    keyed_token_name = _str(request_token.key) + '_request_token'
    keyed_next_name = _str(request_token.key) + '_next'
    session[keyed_token_name] = \
        dict(zip(request_token._fields, request_token))

    if 'next' in request.args:
        session[keyed_next_name] = request.args.get('next')
    else:
        session[keyed_next_name] = 'index'

    return redirect(redirect_to)


@app.route('/logout')
def logout():
    session['mwoauth_access_token'] = None
    session['mwoauth_username'] = None
    if 'next' in request.args:
        return redirect(request.args['next'])
    return redirect(url_for('index'))


@app.route('/oauth-callback')
def oauth_callback():
    request_token_key = request.args.get('oauth_token', 'None')
    keyed_token_name = _str(request_token_key) + '_request_token'
    keyed_next_name = _str(request_token_key) + '_next'

    if keyed_token_name not in session:
        err_msg = "OAuth callback failed. Can't find keyed token. Are cookies disabled?"
        return err_msg

    access_token = handshaker.complete(
        mwoauth.RequestToken(**session[keyed_token_name]),
        request.query_string)
    session['mwoauth_access_token'] = \
        dict(zip(access_token._fields, access_token))

    next_url = url_for(session[keyed_next_name])
    del session[keyed_next_name]
    del session[keyed_token_name]

    get_current_user(False)

    return redirect(next_url)


def get_current_user(cached=True):
    if cached:
        return session.get('mwoauth_username')

    # Get user info
    identity = handshaker.identify(
        mwoauth.AccessToken(**session['mwoauth_access_token']))

    # Store user info in session
    session['mwoauth_username'] = identity['username']
    session['mwoauth_useremail'] = identity['email']

    return session['mwoauth_username']


def _str(val):
    """
    Ensures that the val is the default str() type for python2 or 3
    """
    if str == bytes:
        if isinstance(val, str):
            return val
        else:
            return str(val)
    else:
        if isinstance(val, str):
            return val
        else:
            return str(val, 'ascii')

if __name__ == "__main__":
	app.run(debug=True)
