import { body,check, sanitizeBody }  from  "express-validator";
import userModel from  "../../models/userModel";
import responseCode from '../../helpers/response';

// valication for registation request

class AuthValidation {


	public registration(){
		return [
			body("firstName").matches(/^[a-zA-Z ]{1,20}$/).trim().withMessage("First name has not empty and non-alphanumeric characters."),
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
			body("password").matches(/^(?=.*\d)(?=.*[@$.!%*#?&])(?=.*[a-zA-Z])[a-zA-Z\d@$.!%*#?&]{6,}$/, "i").trim().withMessage("Password must be at least 6 characters in length, one lowercase/uppercase letter, one digit and a special character(@$.!%*#?&)."),
			// Sanitize fields.
			body("firstName").escape(),
			body("lastName").escape(),
			body("email").escape(),
			body("password").escape()
		]
	}

	public login(){
		return [
			body("email").isEmail().withMessage("Email must be a valid email address."),
			body("password").isLength({ min: 1 }).trim().withMessage("Password must be specified."),
			body("email").escape(),
			body("password").escape()
		]
	}
	
  public forgotPassword() {
    return [
      body("email")
        .isEmail()
        .withMessage("Email must be a valid email address."),
    ];
  }

  public otpVerification() {
    return [
      body("email")
        .isEmail()
        .withMessage("Email must be a valid email address."),
      body("otp")
        .isLength({ min: 6 })
        .trim()
        .withMessage("otp must be specified."),
      body("email").escape(),
      body("otp").escape(),
    ];
  }
  public passwordResetting() {
    return [
      body("email")
        .isEmail()
        .withMessage("Email must be a valid email address."),
      body("otp")
        .isLength({ min: 6 })
        .trim()
        .withMessage("otp must be specified."),
      body("email").escape(),
      body("otp").escape(),
      body("newPassword")
        .matches(
          /^(?=.*\d)(?=.*[@$.!%*#?&])(?=.*[a-zA-Z])[a-zA-Z\d@$.!%*#?&]{6,}$/,
          "i"
        )
        .trim()
        .withMessage(
          "at least 6 characters in length, one lowercase/uppercase letter, one digit and a special character(@$.!%*#?&)."
        ).custom((value, { req }) => {
			return new Promise(function (resolve, reject) {
				let password = value;
				let email = req.body.email
				userModel.passwordValidation(email,password,function(error,code){
					if (error) {
						reject(responseCode[code].msg);
					}else{
						resolve(true);
					}
				});	
			});
		  }),

      body("confirmPassword").custom((value, { req }) => {
        return new Promise(function (resolve, reject) {
          if (value == req.body.newPassword) {
            resolve(true);
          } else {
            reject(responseCode["VAL0003"].msg);
          }
        });
      }),
    ];
  }

	public changePassword(){
		return [
			body("currentPassword").custom((password,{req}) => {		
				return new Promise(function(resolve, reject) {
					let userId: number = parseInt(req.headers.userId) || 0;
					userModel.passwordIsExist({userId,password},function(error,code){
						if (error) {
							reject(responseCode[code].msg);
						}else{
							if(password == req.body.newPassword){
								reject(responseCode['VAL0002'].msg);
							}else{
								resolve(true);
							}
						}
					});	
				})
			}),
			body("newPassword").matches(/^(?=.*\d)(?=.*[@$.!%*#?&])(?=.*[a-zA-Z])[a-zA-Z\d@$.!%*#?&]{6,}$/, "i").trim().withMessage("at least 6 characters in length, one lowercase/uppercase letter, one digit and a special character(@$.!%*#?&)."),
		
			body("confirmPassword").custom((value,{req}) => {
				return new Promise(function(resolve, reject) {
					if(value == req.body.newPassword){
						resolve(true);
					}else{
						reject(responseCode['VAL0003'].msg);
					}	
				})
			})
		];
	}

	public editProfile() {
		return [
			body("firstName").optional().matches(/^[a-zA-Z ]{1,20}$/).trim().withMessage("First name has not empty and non-alphanumeric characters."),
			body("firstName").escape(),
		];
	}

	public updateUserStatus(){
		return [
			body("userId").isNumeric().withMessage("Invalid User."),
			body("statusId").isNumeric().trim().withMessage("Invalid Status."),
			body("userId").escape(),
			body("statusId").escape()
		];
	}

	public userIdValidation(){
		return [
			check('userId').isNumeric().trim().withMessage("User Id Should be numeric.").custom((value) => {
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

export default AuthValidation;