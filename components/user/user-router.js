const Router = require('express').Router();
const UserController = require('./user-controller');

Router.post('/register', UserController.register);

module.exports = Router;
