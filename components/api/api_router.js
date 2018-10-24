let router = require('express').Router();

router.get('/', (req, res, next) => {
	console.log(res.header);
	res.sendStatus(404);
});

module.exports = router;
