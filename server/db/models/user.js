'use strict';
module.exports = (sequelize, DataTypes) => {
	var user = sequelize.define('User', {}, {});
	user.associate = function(models) {
		// associations can be defined here
	};
	return user;
};
