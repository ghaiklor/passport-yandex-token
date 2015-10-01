import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

/**
 * `Strategy` constructor.
 * The Yandex authentication strategy authenticates requests by delegating to Yandex using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Yandex App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * Example:
 *     passport.use(new YandexTokenStrategy({
 *           clientID: '123-456-789',
 *           clientSecret: 'shhh-its-a-secret',
 *           passReqToCallback: true
 *       }, function(req, accessToken, refreshToken, profile, next) {
 *              User.findOrCreate(..., function (error, user) {
 *                  next(error, user);
 *              });
 *          }
 *       ));
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @constructor
 */
export default class YandexTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://oauth.yandex.ru/authorize';
    options.tokenURL = options.tokenURL || 'https://oauth.yandex.ru/token';

    super(options, verify);

    this.name = 'yandex-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || 'https://login.yandex.ru/info?format=json';
    this._passReqToCallback = options.passReqToCallback;
    this._oauth2.setAccessTokenName("oauth_token");
    this._oauth2._useAuthorizationHeaderForGET = true;
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} accessToken Yandex OAuth2 access token
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    this._oauth2.get(this._profileURL, accessToken, function (error, body, res) {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error.statusCode));

      try {
        let json = JSON.parse(body);
        let profile = {
          provider: 'yandex',
          id: json.id,
          displayName: json.display_name,
          name: {
            familyName: json.real_name ? json.real_name.split(' ', 2)[0] : '',
            givenName: json.real_name ? json.real_name.split(' ', 2)[1] : ''
          },
          emails: [{value: json.default_email}],
          photos: [],
          _raw: body,
          _json: json
        };

        return done(null, profile);
      } catch (e) {
        return done(e);
      }
    });
  }
}
