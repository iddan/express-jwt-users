/**
 * @module express-jwt-users
 * @see module:express-jwt-users/credentials
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mkdirp = require('mkdirp');
const Express = require('express');
const bodyParser = require('body-parser');
const ExpressJWT = require('express-jwt');
const JWT = require('jsonwebtoken');
const Credentials = require('./credentials');

/**
 * JWT user authentication router
 * @param {Object | Promise} collection Interface to query and save Users.
 * @param {function} collection.insertOne A method to save user document.
 * @param {function} collection.findOne A method to query a user document by it's properties.
 * @param {string} collection.collectionName The name of the collection in the database.
 * @param {string} secretsDir Directory to hold secret files in.
 * @returns {Router} express / connect router
 */
module.exports = function Users ({ collection: collectionPromise, secretsDir }) {
    let router = new Express.Router();
    router.use('/', bodyParser.json());
    router.post('/', Credentials.middleware, (req, res) => {
        Promise.resolve(req.body)
        .then(register)
        .then(res.json.bind(res))
        .catch(error => {
            res.status(400).json(error.message);
        });
    });
    router.post('/authorize', Credentials.middleware, (req, res) => {
        Promise.resolve(req.body)
        .then(authorize)
        .then(res.json.bind(res))
        .catch(error => {
            res.status(403).json(error.message);
        });
    });
    router.all('/authorize', (req, res) => {
        res.status(400).json(`Cannot ${req.method} /authorize, use POST instead`);
    });
    Promise.resolve(collectionPromise)
    .then(collection => {
        router.use(
            '/:user',
            ExpressJWT({
                secret: getRandomBytesFrom(path.join(secretsDir, collection.collectionName)),
                aud: collection.collectionName
            }).unless('/authorize'),
            (err, req, res, next) => {
                if (err.name === 'UnauthorizedError') {
                    return res.status(401).send(err.message);
                }
                return next(err);
            },
            (req, res, next) => {
                if (req.params.user !== req.user.sub) {
                    res.status(401).json(`${req.user.sub} has no permission for this resource`);
                }
                return next();
            }
        );
    });
    return router;
    /**
     * @param {Object} credentials user's credentials to register
     * @param {string} credentials.username user's nickname
     * @param {string} credentials.password user's password
     * @return {Promise} resolves with the DB inseration status
     */
    function register (credentials) {
        return Promise.resolve(collectionPromise)
            .then(collection => collection.insertOne(credentials));
    }
    /**
     * @param {Object} credentials user's credentials to authorize
     * @param {string} credentials.username user's nickname
     * @param {string} credentials.password user's password
     * @returns {Promise} resolves with JWT matching for the user 
     */
    function authorize (credentials) {
        return Promise.resolve(collectionPromise)
            .then(collection => {
                return collection.findOne(credentials)
                .then(user => {
                    if (!user) {
                        throw new Error(`No user was found for the credentials: ${JSON.stringify(credentials)}`);
                    }
                    return JWT.sign({
                        aud: collection.collectionName,
                        sub: credentials.username,
                        context: {
                            user: credentials
                        }
                    }, getRandomBytesFrom(path.join(secretsDir, collection.collectionName)));
                });
            });
    }
};

/**
 * @param {string} secretPath path for a random bytes file to be read or created.
 * @returns {Buffer} crypto random bytes.
 */
function getRandomBytesFrom (secretPath) {
    mkdirp.sync(path.dirname(secretPath));
    try {
        return fs.readFileSync(secretPath);
    }
    catch (err) {
        const secret = crypto.randomBytes(256);
        fs.writeFileSync(secretPath, secret);
        return secret;
    }
}