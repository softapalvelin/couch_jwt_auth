# couch_jwt_auth

couch_jwt_auth is authentication plugin for CouchDB. It accepts JSON Web Token in the Authorization HTTP header and creates CouchDB user context from the token information. couch_jwt_auth doesn't use CouchDB authentication database. User roles are read directly from JWT and not from the authentication database.

The plugin doesn't support unsecured JWTs or digital signature algorithms. Only hash-based message authentication codes are supported. I might add support for digital signature algorithms later. 

## Installation

Install `rebar` if you don't already have it

    $ brew install rebar

Ensure the `plugins` directory exists, e.g.

    $ mkdir /.../couchdb/1.6.0_1/lib/couchdb/plugins

Clone (download) the repo:

    $ git clone https://github.com/softapalvelin/couch_jwt_auth.git

Move the plugin files:

    $ mv couch_jwt_auth /.../couchdb/1.6.0_1/lib/couchdb/plugins

Build the plugin files:

    $ cd /.../couchdb/1.6.0_1/lib/couchdb/plugins/couch_jwt_auth
    $ ./build.sh

Copy default config file to etc folder:

    $ cp /.../couchdb/1.6.0_1/lib/couchdb/plugins/couch_jwt_auth/priv/default.d/jwt_auth.ini /.../couchdb/1.6.0_1/etc/couchdb/default.d/

Add couch_jwt_auth to CouchDB authentication handlers:

    [httpd]
    authentication_handlers = ..., {couch_jwt_auth, jwt_authentication_handler}, ...
    

Restart couchdb

## Test with Curl

    $ curl http://127.0.0.1:5984/_session
You should see `jwt` in the authentication_handlers. Next you can test sending JWT with the request. HMAC secret for this test is `secret` so the Base64URL encoded secret is `c2VjcmV0`. Edit etc/couchdb/local.ini and add the Base64URL encoded secret to the config:

    [jwt_auth]
      hs_secret = c2VjcmV0

Now you can generate JWT from http://jwt.io/. The token is included in the Authorization HTTP header like this:

    $ curl -H "Authorization: Bearer TOKEN_HERE" http://127.0.0.1:5984/_session

With default options you should see the JWT "sub" claim content in the CouchDB username:

    $ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" http://127.0.0.1:5984/_session
    $ {"ok":true,"userCtx":{"name":"1234567890","roles":[]},"info":{"authentication_db":"_users","authentication_handlers":[...,"jwt",...],"authenticated":"jwt"}}


## Use cases

[Auth0](https://auth0.com/) is an identity service that supports many identity providers like Google, Facebook, Twitter and so on. Auth0 generates a JWT that can be parsed by this plugin. [Here](https://github.com/softapalvelin/getting-started-todo) is a sample application that uses Auth0 to authenticate a user with CouchDB.
