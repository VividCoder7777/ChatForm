'use strict';
module.exports = (sequelize, DataTypes) => {
	var user = sequelize.define(
		'User',
		{
			username: {
				type: DataTypes.STRING,
				allowNull: false,
				unique: true
			},
			password: {
				type: DataTypes.STRING,
				allowNull: false
			}
		},
		{}
	);

	user.associate = function(models) {
		// associations can be defined here
	};
	return user;
};
