const Router = require('express').Router();
const UserController = require('./user-controller');

Router.post('/login', UserController.login);
Router.post('/register', UserController.register);
Router.post('/authentication-status', UserController.isAuthenticated);
module.exports = Router;
