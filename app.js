const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const _ = require('lodash');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const randtoken = require('rand-token');
const cors = require('cors');
var morgan = require('morgan');
const low = require('lowdb');

const PORT = process.env.PORT || 3000;
const app = express();

app.use(cors());
app.use(morgan('tiny'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.listen(PORT, function () { console.log(`Server running on ${PORT}`); });

const cp = require('./passport');
const jwtHelper = require('./jwt.config');

const refreshTokens = {};
const dbPath = path.join(__dirname, 'db.json');
const FileAsync = require('lowdb/adapters/FileAsync');
const adapter = new FileAsync(dbPath);
passport.use('jwt', cp.configJWT);

low(adapter).then(function (db) {
    cp.configPassport(db);
    app.post('/api/register', (req, res, next) => {
        let user = {
            userName: req.body.userName,
            email: req.body.email,
            password: req.body.password,
            name: req.body.name,
            surName: req.body.surName
        }

        const existUser = db.get('users').find({ email: user.email }).value();

        if (!existUser) {
            preSave(user, function (u) {
                db.get('users').push(u).write();
                res.status(200).send({
                    status: true,
                    data: 'User registred'
                })
            });
        } else {
            res.status(422).send({
                status: false,
                data: 'Duplicate email adress found.'
            });
        }
    });
    app.post('/api/authenticate', (req, res, next) => {
        passport.authenticate('local', (err, user, info) => {
            if (err) {
                return res.status(400).json(err);
            } else if (user) {
                user = _.pick(user, ['email', 'userName']);
                const refreshToken = randtoken.uid(256);
                refreshTokens[refreshToken] = user.email;
                return res.status(200).send({ status: true, data: { token: generateJWT(user), refreshToken: refreshToken } });
            } else {
                return res.status(401).json(info);
            }
        })(req, res);
    })
    app.get('/api/asd', passport.authenticate('jwt', { session: false }), (req, res) => {
        res.status(200).send('holaaa');
    });
    app.post('/api/refreshToken', jwtHelper.validateToken, (req, res) => {
        let refreshToken = req.body.refreshToken;
        const user = { email: req.body.email, userName: req.body.userName }
        if (refreshToken && refreshTokens[refreshToken]) {
            res.status(200).send({ token: generateJWT(user) });
        } else {
            res.status(404).send({ status: false, data: { message: 'No valid refres token.' } });
        }
    });
});

function preSave(user, callback) {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(user.password, salt, (err, hash) => {
            user.password = hash;
            user.saltSecret = salt;
            callback(user);
        });
    });
}

function generateJWT(user) {
    user = _.pick(user, ['email', 'userName']);
    return jwt.sign(user,
        'SECRET_KEY',
        {
            expiresIn: '10s'
        });
};
