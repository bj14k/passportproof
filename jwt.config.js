const jwt = require('jsonwebtoken');

module.exports.validateToken = function (req, res, next) {
    var token;

    if ('authorization' in req.headers) {
        token = req.headers['authorization'].split(' ')[1];
    }

    if (!token) {
        res.status(403).send({ auth: false, message: 'No token provided.' })
    } else {
        console.log(jwt.decode(token));
        jwt.verify(token, 'SECRET_KEY', (err, decoded) => {
            if (err) {
                return res.status(500).send({ auth: false, message: 'Token authorization failed.' });
            } else {
                req.body.email = decoded.email;
                req.body.userName = decoded.userName
                next();
            }
        });
    }
}