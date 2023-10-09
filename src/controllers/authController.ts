import { Request, Response } from 'express';
import * as moment from 'moment';
import * as jwt from "jsonwebtoken";
import { validationResult } from "express-validator";
import AuthValidation from "./validation/authValidation";
import userModel from "../models/userModel";
import otpModel from "../models/otpModel";
import apiResponse from "../helpers/apiResponse";
import {authenticateJWT} from "../middlewares/jwt";
import * as randomstring from 'randomstring';
import * as mailer from "../helpers/mailer";
import s3 from "../helpers/S3";
import {createLog} from "../models/loggerModel";


class AuthController {
    private authValidation: AuthValidation;

    constructor() {
        this.authValidation = new AuthValidation();
    }


    /**
     * @swagger
     * /auth/register:
     *   post:
     *     tags:
     *       - AuthController
     *     description:
     *       User registration Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Registration object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - firstName
     *             - lastName
     *             - email
     *             - password
     *           properties:
     *             firstName:
     *               type: string
     *             lastName:
     *               type: string
     *             email:
     *               type: string
     *             password:
     *               type: string
     *     responses:
     *       200:
     *         description: User Created Successfully
     * 
     */

    public register(): any {
        return [
            this.authValidation.registration(),
            async (request: Request, response: Response) => {
                try {
                    // Extract the validation errors from a request.
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {

                        let userData = {
                            firstName: request.body.firstName,
                            lastName: request.body.lastName ? request.body.lastName : '',
                            email: request.body.email,
                            password: request.body.password,
                            status: parseInt(process.env.DEFAULT_USER_STATUS_ID),
                            createdBy: request.headers.userId || 1,
                            createdAt: moment(new Date()). format("YYYY-MM-DD HH:mm:ss")
                        };

                        userModel.registration(userData, function (error) {
                            if (!error) {
                                return apiResponse.successResponse(response, "AUTH0001");
                            }

                            return apiResponse.unauthorizedResponse(response, "AUTH0002");
                        })


                    }
                } catch (error) {
                  createLog(error, 'register', null, "authController");
                    //throw error in json response with status 500.
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }
        ]
    }


    /**
     * @swagger
     * /auth/login:
     *   post:
     *     tags:
     *       - AuthController
     *     description: Login Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Login object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - email
     *             - password
     *           properties:
     *             email:
     *               type: string
     *             password:
     *               type: string
     *     responses:
     *       200:
     *         description: Login Successfully
     * 
     */

    public login(): any {
        return [
            this.authValidation.login(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        userModel.emailIsExist(request.body.email, true, function (error, data) {
                            if (!error) {
                                userModel.login({ email: request.body.email, password: request.body.password }, request,  function (error, code, user) {
                                    if (!error && user) {
                                        let userData = user;
                                        //Prepare JWT token for authentication
                                        const jwtPayload = userData;
                                        // const jwtData = {
                                        // 	expiresIn: process.env.JWT_TIMEOUT_DURATION,
                                        // };
                                        const secret = process.env.JWT_SECRET;
                                        //Generated JWT token with Payload and secret.
                                        userData.token = jwt.sign(jwtPayload, secret);
                                        response.cookie('token', userData.token, { httpOnly: true, sameSite: 'none', secure: true });
                                        console.log("cookie set on server ==>>>",userData.token);  // remove this line after resolving cookie issue
                                        
                                        return apiResponse.successResponseWithData(response, "AUTH0007", userData);
                                    } else {
                                        return apiResponse.unauthorizedResponse(response, code);
                                    }
                                });
                            } else {
                                return apiResponse.unauthorizedResponse(response, "AUTH0005");
                            }
                        });

                    }
                } catch (error) {
                  createLog(error, 'login', null, "authController");
                    return apiResponse.ErrorResponse(response, error);
                }
            }];

    }

    /**
     * @swagger
     * /auth/forgot-password:
     *   post:
     *     tags:
     *       - AuthController
     *     description: forgot password Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: forgot password object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - email
     *           properties:
     *             email:
     *               type: string
     *     responses:
     *       200:
     *         description: eamil sent Successfully
     *
     */

    public forgotPassword(): any {
      return [
        this.authValidation.forgotPassword(),
        async (request: Request, response: Response) => {
          try {
            const errors = validationResult(request);
            if (!errors.isEmpty()) {
              return apiResponse.validationErrorWithData(
                response,
                "GEN0003",
                errors.array()
              );
            } else {
              const email = (request.body.email || '').trim();
              userModel.emailIsExist(
                email,
                true,
                async function (error, data) {
                  if (!error) {
                    //Generate OTP
                    const otp = randomstring.generate({
                        length: 6,
                        charset: 'numeric'
                    });
                    const minutesToExpire = 10;
                    otpModel.insertNewOtp(data.id, otp + '', minutesToExpire, function(errCode: string, otpObj: any) {
                      if (!errCode) {
                        // code for sending email
                        mailer.send(process.env.EMAIL_ADDRESS, email, 'OTP for reset password', `Your otp for resetting password is ${otp}. 
                        Please don't share it with anyone. 
                        This OTP will expire in ${minutesToExpire} minutes.`, (err, result) => {
                            if (err) {
                              return apiResponse.validationErrorWithData(response, 'GEN0004',err);
                              
                            } else{
                              return apiResponse.successResponseWithData(
                                response,
                                "AUTH0016",
                                {
                                  message: "OTP sent successfully",
                                }
                              );
                            }
                        });
                      } else {
                        return apiResponse.unauthorizedResponse(response, errCode);
                      }
                    });
                  } else {
                    return apiResponse.unauthorizedResponse(response, "AUTH0005");
                  } 
                }
              );
            } 
          } catch (error) {
            createLog(error, 'forgotPassword', null, "authController");
            return apiResponse.ErrorResponse(response, error);
          }
        }
      ]
    }
                    

    /**
     * @swagger
     * /auth/verify-otp:
     *   post:
     *     tags:
     *       - AuthController
     *     description: otp Verification Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: otp Verification object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - email
     *             - otp
     *           properties:
     *             email:
     *               type: string
     *             otp:
     *               type: string
     *     responses:
     *       200:
     *         description: otp verified Successfully
     *
     */

    public otpVerification(): any {
      return [
        this.authValidation.otpVerification(),
        async (request: Request, response: Response) => {
          try {
            const errors = validationResult(request);
            // if (!errors.isEmpty()) {
            //   return apiResponse.validationErrorWithData(
            //     response,
            //     "GEN0003",
            //     errors.array()
            //   );
            // } else {
              userModel.emailIsExist(
                request.body.email,
                true,
                async function (error, data) {
                  if (!error) {
                    const otp = (request.body.otp || '').trim();
                    otpModel.getOTPByUserId(data.id, function(errCode: string, otpObj: any){
                      if(otpObj && otpObj.otp === otp) {
                        return apiResponse.successResponseWithData(
                          response,
                          "AUTH0015",
                          {
                            message: "Success",
                          }
                        );                      
                      } else {
                        return apiResponse.unauthorizedResponse(response, "AUTH0017");
                      }
                    });
                  } else {
                    return apiResponse.unauthorizedResponse(response, "AUTH0005");
                  } 
                }
              );
            // }
          } catch (error) {
            return apiResponse.ErrorResponse(response, error);
          }
        },
      ];
    }


/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     tags:
 *       - AuthController
 *     description: reset password Api
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: reset password object
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           required:
 *             - email
 *             - otp
 *             - newPassword
 *             - confirmPassword
 *           properties:
 *             email:
 *               type: string
 *             otp:
 *               type: string
 *             newPassword:
 *               type: string
 *             confirmPassword:
 *               type: string
 *     responses:
 *       200:
 *         description: reset password Successfully
 *
 */

 public passwordResetting(): any {
  return [
    this.authValidation.passwordResetting(),
    async (request: Request, response: Response) => {
      try {
        const errors = validationResult(request);
        if (!errors.isEmpty()) {
            return apiResponse.validationErrorWithData(
                response,
                "GEN0003",
                errors.array()
            );
        } else {
          userModel.emailIsExist(
            request.body.email,
            true,
            async function (error, data) {
              if (!error) {
                const otp = (request.body.otp || '').trim();
                otpModel.getOTPByUserId(data.id, function(errCode: any, otpObj: any){
                  if(otpObj && otpObj.otp === otp) {
                    let newPassword = (request.body.newPassword || '').trim();
                    userModel.updatePassword({
                      password: newPassword,
                      userId: data.id
                    }, async function (error:any, code:any) {
                        if (error) {
                          return apiResponse.ErrorResponse(response, code);
                        } else {
                          otpModel.deleteOtp(data.id, function(errCode: any, deleteOtpObj: any){
                            if(!errCode) {
                              return apiResponse.successResponse(response, errCode);
                            } else {
                              return apiResponse.successResponse(response, code);
                            }
                          });
                        }
                    });
                  } else {
                    return apiResponse.unauthorizedResponse(response, "AUTH0017");
                  }
                });
              } else {
                return apiResponse.unauthorizedResponse(response, "AUTH0005");
              }
            }
          );
        }
    } catch (error) {
        // return apiResponse.ErrorResponse(response, error);
      }
    },
  ];
}


    /**
     * @swagger
     * /auth/change-password:
     *   put:
     *     tags:
     *       - AuthController
     *     description: Change password Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Request object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - currentPassword
     *             - newPassword
     *             - confirmPassword
     *           properties:
     *             currentPassword:
     *               type: string
     *             newPassword:
     *               type: string
     *             confirmPassword:
     *               type: string
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: Password Updated Successfully.
     * 
     */

    public changePassword(): any {
        return [
            authenticateJWT,
            this.authValidation.changePassword(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        let userId: any = request.headers.userId;
                        let password: string = request.body.newPassword;

                        userModel.updatePassword({ userId, password }, function (error, code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponse(response, code);
                            }
                        })
                    }

                } catch (err) {
                  createLog(err, 'changePassword', null, "authController");
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }

    /**
     * @swagger
     * /auth/edit-profile:
     *   put:
     *     tags:
     *       - AuthController
     *     description: Update user profile detail
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Request object
     *         in: body
     *         required: false
     *         schema:
     *           type: object
     *           properties:
     *             firstName:
     *               type: string
     *             lastName:
     *               type: string
     *             avatar:
     *               type: string
     *             phone:
     *               type: number
     *             address:
     *               type: string
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: Profile Updated Successfully.
     * 
     */

    public editProfile(): any {
        return [
            authenticateJWT,
            this.authValidation.editProfile(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        let data = {
                            userId:request.headers && request.headers.userId ? request.headers.userId: 0,
                            firstName: request.body.firstName ? request.body.firstName:null,
                            lastName: request.body.lastName != null ? request.body.lastName:null,
                            phone: request.body.phone != null ? request.body.phone:null,
                            avatar: request.body.avatar != null ? request.body.avatar:null,
                            address: request.body.address != null ? request.body.address:null,
                            email: request.body.email !==null ? request.body.email : null,
                            companyId : request.body.companyId !==null ? request.body.companyId : null,
                            productCategories: request.body.productCategories !==null ? request.body.productCategories : null,
                            updatedBy: request.headers.userId ? request.headers.userId: null,
                            updatedAt: moment(new Date()). format("YYYY-MM-DD HH:mm:ss")
                        }

                        userModel.updateProfile(data, function (error, code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponse(response, code);
                            }
                        })
                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }

    /**
     * @swagger
     * /auth/update-user-status:
     *   put:
     *     tags:
     *       - AuthController
     *     description: Update user status
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Request object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - userId
     *             - statusId
     *           properties:
     *             userId:
     *               type: number
     *             statusId:
     *               type: number
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: User Status Updated Successfully.
     * 
     */

    public updateUserStatus(): any{
        return [
            authenticateJWT,
            this.authValidation.updateUserStatus(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        let data = {
                            userId: request.body.userId ? parseInt(request.body.userId): null,
                            statusId: request.body.statusId,
                            updatedBy: request.headers.userId ? request.headers.userId: null,
                            updatedAt: moment(new Date()). format("YYYY-MM-DD HH:mm:ss")
                        }

                        userModel.updateUserStatus(data, function (error, code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponse(response, code);
                            }
                        })
                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }


    /**
     * @swagger
     * /auth/delete-user/{userId}:
     *   delete:
     *     tags:
     *       - AuthController
     *     summary: Delete a user by ID
     *     parameters:
     *       - in: path
     *         name: userId
     *         schema:
     *           type: integer
     *         required: true
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: user ID of the user to delete
     *     responses:
     *       200:
     *         description: User deleted Successfully.
     * 
     */

    public deleteUser(): any{
        return [
            authenticateJWT,
            this.authValidation.userIdValidation(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        
                        userModel.deleteUser(parseInt(request.params.userId), function (error, code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponse(response, code);
                            }
                        })
                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }


    /**
     * @swagger
     * /auth/user-details/{userId}:
     *   get:
     *     tags:
     *       - AuthController
     *     summary: Get a user by ID
     *     parameters:
     *       - in: path
     *         name: userId
     *         schema:
     *           type: integer
     *         required: true
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: Get a user by ID
     *     responses:
     *       200:
     *         description: Get User detail Successfully.
     * 
     */

    public userDetail():any {
        return [
            authenticateJWT,
            this.authValidation.userIdValidation(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        
                        userModel.getUserDetail(parseInt(request.params.userId), function (error, data,code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponseWithData(response, code, data);
                            }
                        })
                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }


    /**
     * @swagger
     * /auth/user-list:
     *   get:
     *     tags:
     *       - AuthController
     *     summary: Get a user list
     *     parameters:
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: Get a user list
     *     responses:
     *       200:
     *         description: Get User List Successfully.
     * 
     */

    public userList():any {
        return [
            authenticateJWT,
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        
                        userModel.getUserList(function (error, data,code) {
                            if (error) {
                                return apiResponse.ErrorResponse(response, code);
                            } else {
                                return apiResponse.successResponseWithData(response, code, data);
                            }
                        })
                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }];
    }

    /**
     * @swagger
     * /auth/update-profile:
     *   put:
     *     tags:
     *       - AuthController
     *     description: Update user profile detail
     *     consumes:
     *       - multipart/form-data
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: formData
     *         name: avatar
     *         type: file
     *         required: false
     *       - in: formData
     *         name: firstName
     *         type: string
     *         required: false
     *       - in: formData
     *         name: lastName
     *         type: string
     *         required: false
     *       - in: formData
     *         name: countryCode
     *         type: integer
     *         required: false
     *       - in: formData
     *         name: phone
     *         type: integer
     *         required: false
     *       - in: formData
     *         name: address
     *         type: string
     *         required: false
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: Profile Updated Successfully.
     * 
     */

    public updateProfile(): any {
      return [
          authenticateJWT,
          this.authValidation.editProfile(),
          async (request: Request, response: Response) => {
              try {
                  const errors = validationResult(request);
                  if (!errors.isEmpty()) {
                      // Display sanitized values/errors messages.
                      return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                  } else {
                    let subFolderName = randomstring.generate({
                      length: 6,
                      charset: 'alphabetic'
                    });
                    let FilesRequest = request.files ? request.files : [];
                    let updatedData = {
                      userId: request.headers && request.headers.userId ? request.headers.userId : 0,
                      firstName: request.body.firstName ? request.body.firstName : null,
                      lastName: request.body.lastName ? request.body.lastName : null,
                      countryCode: request.body.countryCode ? request.body.countryCode : null,
                      phone: request.body.phone ? request.body.phone : null,
                      address: request.body.address ? request.body.address : null,
                      updatedBy: request.headers.userId ? request.headers.userId : null,
                    }

                    if (FilesRequest.length > 0) {
                      s3.uploadFileToLocalAndSaveToS3('uploadUserDocs', 'users/images', subFolderName, request, response, ['images'], updatedData.userId, function (err: any, docName: any) {
                        if (err) {
                          return apiResponse.ErrorResponse(response, "PRODUCT0010");
                        } else {
                          docName.forEach(function (name, index) {
                            updatedData["avatar"] = name;
                          })
                          userModel.updateUserProfile(updatedData, function (error, code, data) {
                            if (error) {
                              return apiResponse.ErrorResponse(response, code);
                            } else {
                              return apiResponse.successResponseWithData(response, code, data);
                            }
                          })
                        }
                      });
                    } else {
                      updatedData['avatar'] = null;
                      userModel.updateUserProfile(updatedData, function (error, code, data) {
                        if (error) {
                          return apiResponse.ErrorResponse(response, code);
                        } else {
                          return apiResponse.successResponseWithData(response, code, data);
                        }
                      })
                    }
                  }
              } catch (err) {
                  return apiResponse.ErrorResponse(response, "GEN0004");
              }
          }];
    }
}

export default AuthController