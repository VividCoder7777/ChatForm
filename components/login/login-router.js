let Router = require('express').Router();
let controller = require('./login-controller');

Router.get('/', controller.authenticate());

module.exports = Router;
