const { body, validationResult } = require('express-validator/check');
const { sanitizeBody } = require('express-validator/filter');
const User = require('../../server/db/models').User;
const bcrypt = require('bcryptjs');

module.exports.login = [
	body('username')
		.isEmail()
		.withMessage('Username must be an email')
		.not()
		.isEmpty()
		.withMessage('Username must not be empty')
		.custom((value) => {
			return User.findOne({
				where: {
					username: value
				}
			}).then((user) => {
				if (!user) {
					return Promise.reject('Username does not have an account');
				}
			});
		}),
	body('password').not().isEmpty().withMessage('Password must not be empty'),
	sanitizeBody('*').trim().escape(),
	(req, res, next) => {
		const errors = validationResult(req);

		if (!errors.isEmpty()) {
			res.json({
				errors: errors.array()
			});
		}

		User.findOne({
			where: {
				username: req.body.username
			}
		}).then((user) => {
			if (user) {
				const hashedPassword = hashPassword(req.body.password);

				if (hashedPassword !== user.password) {
					// error
					res.json({
						errors: [ 'Password is incorrect' ]
					});
				} else {
					// redirect to home and do session thing here or jsonwebtoken
					res.json({
						redirect: '/'
					});
				}
			}
		});
	}
];

module.exports.register = [
	body('username')
		.custom((value) => {
			// TODO: this is placed inside the custom validation
			return User.findOne({
				where: {
					username: value
				}
			}).then((user) => {
				if (user) {
					return Promise.reject('Username has already been taken');
				}
			});
		})
		.isEmail()
		.withMessage('Username has to be an email')
		.matches(/^[a-zA-Z0-9@.]*$/)
		.withMessage('Username can only contain characters, numbers and some special characters'),
	body('password').isLength(7).withMessage('Password must be at least 7 characters long'),
	sanitizeBody('*').trim().escape(),
	(req, res, next) => {
		req.checkBody('retypepassword', 'Passwords do not match').equals(req.body.password);
		req.validationErrors();

		const errors = validationResult(req);

		// there are errors
		if (!errors.isEmpty()) {
			res.json({
				errors: errors.array()
			});
		} else {
			// has password
			const hash = hashPassword(req.body.password);

			User.create({
				username: req.body.username,
				password: hash
			}).then((user) => {
				// create user and send back redirect url
				res.status(201).json({
					redirect: '/login',
					message: 'Your Account Has Been Successfully Created.'
				});
			});
		}
	}
];

function hashPassword(password) {
	const salt = bcrypt.genSaltSync(10);
	const hash = bcrypt.hashSync(password, salt);

	return hash;
}
