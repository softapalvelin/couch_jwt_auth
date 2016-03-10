# couch_jwt_auth

couch_jwt_auth is authentication plugin for CouchDB. It accepts JSON Web Token in the Authorization
HTTP header and creates CouchDB user context from the token information. couch_jwt_auth doesn't use
CouchDB authentication database. User roles are read directly from JWT and not from the
authentication database.

The plugin doesn't support unsecured JWTs or digital signature algorithms. Only hash-based message
authentication codes are supported. I might add support for digital signature algorithms later. 

If you want to learn more around JWT itself, [the intro](https://jwt.io/introduction/) on their
site is just amazing and explains the concepts really well.

## Installation

1. Install `rebar` if you don't already have it, which is used to compile the Erlang project.
  ```
  $ brew install rebar
  ```

2. Clone (download) the repo:
  ```
  $ git clone https://github.com/softapalvelin/couch_jwt_auth.git
  ```

3. Build the plugin files:
  ```
  $ cd couch_jwt_auth $ ./build.sh $ make plugin
  ```

4. Find where CouchDB is installed:
  ```
  $ brew info couchdb | grep Cellar
  ```

  It should ouput something like: `/usr/local/Cellar/couchdb/1.6.1_3 (657 files, 17M) *`, a path like
  the one at the beginning (`/usr/local/Cellar/couchdb/1.6.1_3`) is what you're after :).  That's
  CouchDB's root in your Mac. Use whatever your local path is in the following commands:

5. Ensure the `plugins` directory exists:
  ```
  $ mkdir -p /usr/local/Cellar/couchdb/1.6.1_3/lib/couchdb/plugins
  ```

6. Move the plugin to CouchDB's plugins folder:
  ```
  $ mv couch_jwt_auth-1.0.1-18-1.6.1 /usr/local/Cellar/couchdb/1.6.1_3/lib/couchdb/plugins/couch_jwt_auth
  ```

7. Configure the couch_jwt_auth:

  Copy the default config file to CouchDB's etc folder:
  ```
  $ cp /usr/local/Cellar/couchdb/1.6.1_3/lib/couchdb/plugins/couch_jwt_auth/priv/default.d/jwt_auth.ini /usr/local/etc/couchdb/default.d
  ```

  Edit `/usr/local/etc/couchdb/default.d/jwt_auth.ini` and at least change the `hs_secret` value. This
  is your JWT shared secret that you will use somewhere else to authenticate with.  This value has to
  be encoded in `base64`. `openssl` can help us with that. Choose a secret like `supersecret` :) and
  run this:

  ```
  echo -n 'supersecret' | openssl base64
  ```

  It will output a `base64` string like `c3VwZXJzZWNyZXQ=`, put that in like:

  ```
  hs_secret = c3VwZXJzZWNyZXQ=
  ```

  [Here's a nice command to get a random
  secret](http://security.stackexchange.com/questions/81976/is-this-a-secure-way-to-generate-passwords-at-the-command-line):

  ```
  openssl rand -base64 32 | tr -d /=+ | cut -c -30
  ```

  If you're using `couchdb-jwt-auth-server` to leverage authentication through the `_users` db (see
  below), make sure that you set `username_claim` to this:

  ```
  username_claim=name
  ```

  This means that instead of using `sub` as the `username_claim`, it uses `name` which is the field
  that CouchDB uses in its `_users` database to tell users apart. [This wiki page](https://github.com/softapalvelin/couch_jwt_auth/wiki/Configuration-options) contains more information about configuration options.

  Edit `/usr/local/etc/couchdb/local.ini` and add `couch_jwt_auth` to CouchDB's `authentication_handlers`
  `httpd` section. It's ok to have more options on that line :):

  ```
  [httpd]
  authentication_handlers = ..., {couch_jwt_auth, jwt_authentication_handler}, ...
  ```

8. Restart couchdb and you're good to go.

Note that you can copy the same compiled plugin to your production instance of CouchDB.
In my Ubuntu deployment of CouchDB, the plugins live at `/usr/lib/x86_64-linux-gnu/couchdb/plugins`.
So the steps are the same apart from the fact that you may need to push the built file somehow.

Alternatively, you can try to push it through CouchDB's HTTP API but it doesn't seem to work at all
times. [See this post for more on how to go about it](http://mail-archives.apache.org/mod_mbox/couchdb-user/201509.mbox/%3C1441288345556.82527.207338@webmail4%3E).

## Test with Curl

```
$ curl http://127.0.0.1:5984/_session
```

You should see `jwt` in the authentication_handlers. Next
you can test sending JWT with the request. HMAC secret for this test is `secret` so the
Base64URL encoded secret is `c2VjcmV0`.

Now you can generate a sample JWT from http://jwt.io. The token is included in the Authorization
HTTP header like this:

```
$ curl -H "Authorization: Bearer TOKEN_HERE" http://127.0.0.1:5984/_session
```

With default options you should see the JWT "sub" claim content in the CouchDB username:

```
$ curl -H "Authorization: Bearer
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
http://127.0.0.1:5984/_session
```

will output:

```
$ {"ok":true,"userCtx":{"name":"1234567890","roles":[]},"info":{"authentication_db":"_users","authentication_handlers":[...,"jwt",...],"authenticated":"jwt"}}
```

## Use cases

[Auth0](https://auth0.com/) is an identity service that supports many identity providers like
Google, Facebook, Twitter and so on. Auth0 generates a JWT that can be parsed by this plugin.
[Here](https://github.com/softapalvelin/getting-started-todo) is a sample application that uses
Auth0 to authenticate a user with CouchDB.

If you want to leverage CouchDB's `_users` database as your authentication mechanism you still can!
Have a look at [couchdb-jwt-auth-server](https://github.com/BeneathTheInk/couchdb-jwt-auth-server)
for a NodeJS implementation that allows you to generate JWT tokens that this plugin can consume.

[The motivation section in
couchdb-jtw-auth-server](https://github.com/BeneathTheInk/couchdb-jwt-auth-server#motivation)
explains very well how and why you would want to use this approach over cookies.


Apache v2.0 license.
