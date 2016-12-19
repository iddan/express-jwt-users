/**
 * @module express-jwt-users/credentials
 * @see module:express-jwt-users
 */

const JSONSchema = require('jsonschema');

const PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[~`!@#$%^&*()-_+={}[\]|;:"<>,./?]).{8,}$/;
/**
 * Validate username-password credentials document
 * @param {Object} credentials - user credentials
 * @returns {ValidatorResult} - of the validation of the credentials
 */
const validate = exports.validate = (credentials) =>
    JSONSchema.validate(
        credentials,
        {
            properties: {
                username: {
                    type: 'string',
                    pattern: '^[a-z0-9_]+$'
                },
                password: {
                    type: 'string',
                    pattern: PASSWORD_REGEX.source.toString()
                }
            },
            required: [ 'username', 'password' ],
        },
        {
            throwError: true
        }
    );

/**
 * @param {Request} req - HTTP Request
 * @param {Response} res - HTTP Response
 * @param {function} next - Connect next function
 * @returns {void}
 */
exports.middleware = (req, res, next) => {
    try {
        validate(req.body);
        next();
    }
    catch (err) {
        if (err.property === 'instance.password') {
            res.status(400).json('Password should be at least 8 chars long and include a capital letter, a small letter, a digit and a special char.');
        }
        else if (err.property === 'instance.username') {
            res.status(400).json('Username should only include small letters, digits and underscores.');
        }
        else {
            res.status(400).json('An error ecured while validating the provided credentials. Make sure the is at least 8 chars long and includes a capital letter, a small letter, a digit and a special char, and the username only includes small letters, digits and underscores.');
        }
    }
};