import os
basedir = os.path.abspath(os.path.dirname(__file__))


class config(object):
    DEBUG = False
    TESTING = False


class production(config):
    DEBUG = False
    CONSUMER_KEY = ""
    CONSUMER_SECRET = ""
    OAUTH_MWURI = "https://meta.wikimedia.org/w/"
    SESSION_COOKIE_NAME = 'wikicontest'
    SESSION_COOKIE_PATH = '/wikicontest'
    SESSION_COOKIE_SECURE = True
    SESSION_REFRESH_EACH_REQUEST = False
    PREFERRED_URL_SCHEME = 'https'


class local(config):
    DEVELOPMENT = True
    DEBUG = True
    CONSUMER_KEY = "c13c308a51b8129eccc88e1509c97cae"
    CONSUMER_SECRET = "134341041cfc0083ca509492fab247d91b6e58a9"
    OAUTH_MWURI = "http://192.168.64.3"