const { body, validationResult } = require('express-validator/check');
const { sanitizeBody } = require('express-validator/filter');
const User = require('../../server/db/models').User;

module.exports.register = [
	body('username').isLength({ min: 7 }).withMessage('Username must be at least 7 characters').custom((value) => {
		console.log('value is ' + value);
	}),
	sanitizeBody('*').trim().escape(),
	(req, res, next) => {
		const errors = validationResult(req);

		console.log(User);
		User.findOne({
			where: {
				username: req.body.username
			}
		}).then((user) => {
			console.log(user);
		});
		res.send('hi');
		// if (!errors.isEmpth()) {
		// 	res.status(422).json({
		// 		errors: errors.array()
		// 	});
		// } else {
		// }
	}
];

module.exports.login = (req, res, next) => {};
