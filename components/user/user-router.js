const Router = require('express').Router();
const UserController = require('./user-controller');

Router.post('/login', UserController.login);
Router.post('/register', UserController.register);

module.exports = Router;
