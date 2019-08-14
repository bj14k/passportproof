const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');

module.exports.configPassport = function (db) {
    passport.use(
        new LocalStrategy({ usernameField: 'email' },
            (email, password, done) => {
                const user = db.get('users').find({ email: email }).value();
                if (comparePasswords(password, user.password)) {
                    return done(null, user);
                }
                return done(null, false);
            })
    );
}

const opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = 'SECRET_KEY';

module.exports.configJWT = new JwtStrategy(opts, (jwt_payload, done) => {
    var expirationDate = new Date(jwt_payload.exp * 1000);
    if (expirationDate < new Date()) {
        return done(null, false);
    }
    return done(null, true);
})

function comparePasswords(userPassword, passwordDb) {
    return bcrypt.compareSync(userPassword, passwordDb);
}