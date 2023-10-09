import { body,check, sanitizeBody }  from  "express-validator";
import userModel from  "../../models/userModel";
import responseCode from '../../helpers/response';

// valication for registation request

class UserManagementValidation {

	public isUserExist(){
		return [
			body("email").isEmail().withMessage("Email must be a valid email address.")
		]
	}

	public createUser(){
		return [
			body("firstName").matches(/^[a-zA-Z]{1,}[a-zA-Z ]{1,20}$/).trim().withMessage("First name has not empty and non-alphanumeric characters."),
			body("email").isEmail().withMessage("Email must be a valid email address.").custom((value) => {
				return new Promise(function(resolve, reject) {
					userModel.emailIsExist(value,false,function(error,data){							
						if (!error) {
							reject(responseCode['VAL0001'].msg);
						}else{
							resolve(false);
						}
					});
				});
			}),
			body("address").optional().isLength({ max: 250 }).trim().withMessage("Address length should be under 250 char."),

			// Sanitize fields.
			body("firstName").escape(),
			body("lastName").escape(),
			body("email").escape(),
			body("password").escape()
		]
	}

	public editProfile(){
		return [
			body("firstName").optional().matches(/^[a-zA-Z]{1,}[a-zA-Z ]{1,20}$/).trim().withMessage("First name has not empty and non-alphanumeric characters."),
			body("address").optional().isLength({ max: 250 }).trim().withMessage("Address length should be under 250 char."),
			body("email").optional().isEmail().withMessage("Email must be a valid email address.")
		];
	}

	public getUsersList() {
		return [
			body("currentStatus").optional().isNumeric().withMessage("Current Status Id Should be numeric."),
			body("role").optional().isNumeric().withMessage("Role Should be numeric."),
			body("lastUpdatedBy").optional().isNumeric().withMessage("User Id Should be numeric."),
			body("page").optional().isNumeric().withMessage("page Should be numeric."),
			body("limit").optional().isNumeric().withMessage("Limit Should be numeric."),

		];
	}

	public userIdValidation(){
		return [
			body('*.userId').isNumeric().trim().withMessage("User Id Should be numeric.").custom((value) => {
				return new Promise(function(resolve, reject) {
					userModel.userIsExist(value,function(error,data){							
							if (error) {
								reject(responseCode['VAL0004'].msg);
							}else{
								resolve(false);
							}
						});
					});
			}),
		]
	}
}

export default UserManagementValidation;