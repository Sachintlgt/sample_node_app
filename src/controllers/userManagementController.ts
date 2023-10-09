import { Request, Response } from 'express';
import * as moment from 'moment';
import * as jwt from "jsonwebtoken";
import { validationResult } from "express-validator";
import UserManagementValidation from "./validation/userManagementValidation";
import userModel from "../models/userModel";
import apiResponse from "../helpers/apiResponse";
import {authenticateJWT} from "../middlewares/jwt";
import * as randomstring from 'randomstring';
import * as mailer from "../helpers/mailer";

class userManagementController {
    private userManagementValidation: UserManagementValidation;

    constructor() {
        this.userManagementValidation = new UserManagementValidation();
    }


    /**
     * @swagger
     * /users/get-roles-count:
     *   get:
     *     tags:
     *       - UserManagementController
     *     summary: Get a user roles count
     *     parameters:
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: Get a user by ID
     *     responses:
     *       200:
     *         description: user roles count display successfully.
     * 
     */

    public getUserRoleCount():any {
        return [
            authenticateJWT,
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {
                        
                        userModel.getUserRoleCount(function (error, data,code) {
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
     * /users/filters-list:
     *   get:
     *     tags:
     *       - UserManagementController
     *     summary: Get filters list
     *     parameters:
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: Get filters list
     *     responses:
     *       200:
     *         description: Filters list display Successfully.
     * 
     */

    public getUserFilterList(): any {
      return [
          authenticateJWT,
          async (request: Request, response: Response) => {
              try {
                  const errors = validationResult(request);
                  if (!errors.isEmpty()) {
                      // Display sanitized values/errors messages.
                      return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                  } else {

                      userModel.getUserFilterList(function (error, data, code) {
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
          }
      ]
  }


    /**
     * @swagger
     * /users/user-details/{userId}:
     *   get:
     *     tags:
     *       - UserManagementController
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

    public getUserDetail():any {
      return [
          authenticateJWT,
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
          }
      ];
    }


    /**
     * @swagger
     * /users/edit-profile/{userId}:
     *   put:
     *     tags:
     *       - UserManagementController
     *     description: Update user profile detail
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: path
     *         name: userId
     *         schema:
     *           type: integer
     *         required: true
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
     *             status:
     *               type: number
     *             companyId:
     *               type: string
     *             productCategories:
     *               type: string
     *             roleIds:
     *               type: array
     *               items:
     *                 type: number
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
          this.userManagementValidation.editProfile(),
          async (request: Request, response: Response) => {
              try {
                  const errors = validationResult(request);
                  if (!errors.isEmpty()) {
                      // Display sanitized values/errors messages.
                      return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                  } else {
                      let data = {
                          userId: request.params.userId ? request.params.userId : 0,
                          firstName: request.body.firstName ? request.body.firstName : null,
                          lastName: request.body.lastName !== null ? request.body.lastName : null,
                          email: request.body.email !== null ? request.body.email : null,
                          phone: request.body.phone !== null ? request.body.phone : null,
                          avatar: request.body.avatar !== null ? request.body.avatar : null,
                          address: request.body.address !== null ? request.body.address : null,
                          status: request.body.status !== null ? request.body.status : null,
                          roles: request.body.roleIds !== null ? request.body.roleIds : null,
                          updatedBy: request.headers.userId ? request.headers.userId : null,
                          companyId : request.body.companyId !== null ? request.body.companyId : null,
                          productCategories: request.body.productCategories !== null ? request.body.productCategories : null,
                          updatedAt: moment(new Date()).format("YYYY-MM-DD HH:mm:ss")
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
     * /users/get-roles-list:
     *   get:
     *     tags:
     *       - UserManagementController
     *     summary: Get a role list
     *     parameters:
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *         description: Get a role list
     *     responses:
     *       200:
     *         description: Role list display Successfully.
     * 
     */

    public getUserRolesList(): any {
      return [
          authenticateJWT,
          async (request: Request, response: Response) => {
              try {
                  const errors = validationResult(request);
                  if (!errors.isEmpty()) {
                      // Display sanitized values/errors messages.
                      return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                  } else {

                      userModel.getUserRolesList(function (error: boolean, data: any) {

                          if (!error) {
                              return apiResponse.successResponseWithData(response, "USER0003", data);
                          }

                          return apiResponse.unauthorizedResponse(response, "GEN0007");
                      })

                  }

              } catch (err) {
                  return apiResponse.ErrorResponse(response, "GEN0004");
              }
          }
      ]
  }

    /**
     * @swagger
     * /users/create-user:
     *   post:
     *     tags:
     *       - UserManagementController
     *     description:
     *       User creation Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: User creation object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - firstName
     *             - lastName
     *             - email
     *             - phone
     *             - address
     *             - avatar
     *             - productCategories
     *             - comapnyId
     *             - roleIds
     *           properties:
     *             firstName:
     *               type: string
     *             lastName:
     *               type: string
     *             email:
     *               type: string
     *             phone:
     *               type: number
     *             address:
     *               type: string
     *             avatar:
     *               type: string
     *             productCategories:
     *               type: string
     *             companyId:
     *               type: string
     *             roleIds:
     *               type: array
     *               items:
     *                 type: number
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: User Created Successfully
     * 
     */

    public createUser(): any {
      return [
          authenticateJWT,
          this.userManagementValidation.createUser(),
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
                          phone: request.body.phone ? request.body.phone : null,
                          address: request.body.address ? request.body.address : null,
                          roleIds: request.body.roleIds ? request.body.roleIds : null,
                          avatar: request.body.avatar ? request.body.avatar : null,
                          companyId : request.body.companyId ? request.body.companyId : null,
                          productCategories: request.body.productCategories ? request.body.productCategories : null,
                          status: parseInt(process.env.DEFAULT_USER_STATUS_ID),
                          createdBy: request.headers.userId || 0
                      };

                      userModel.createUser(userData, function (error) {
                          if (!error) {
                              return apiResponse.successResponse(response, "AUTH0001");
                          }

                          return apiResponse.unauthorizedResponse(response, "AUTH0002");
                      })


                  }
              } catch (error) {
                  //throw error in json response with status 500.
                  return apiResponse.ErrorResponse(response, "GEN0004");
              }
          }
      ]
  }

    /**
     * @swagger
     * /users/get-users-list:
     *   post:
     *     tags:
     *       - UserManagementController
     *     description:
     *       Get Users List Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: object
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           properties:
     *             searchColumnList:
     *               type: array
     *               items:
     *                 type: string
     *             searchString:
     *               type: string
     *             currentStatus:
     *               type: number
     *             role:
     *               type: number
     *             lastUpdatedBy:
     *               type: number
     *             createdPeriod:
     *               type: number
     *             lastUpdatedPeriod:
     *               type: number
     *             page:
     *               type: number
     *             limit:
     *               type: number
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: Users list display Successfully
     * 
     */

    public getUsersList(): any {
        return [
            authenticateJWT,
            this.userManagementValidation.getUsersList(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {

                        userModel.getUsersList(request, function (error: boolean, data: any) {

                            if (!error) {
                                return apiResponse.successResponseWithData(response, "USER0004", data);
                            }

                            return apiResponse.unauthorizedResponse(response, "GEN0007");
                        })

                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }
        ]
    }

    /**
     * @swagger
     * /users/update-status:
     *   put:
     *     tags:
     *       - UserManagementController
     *     description:
     *       Update users status Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: Array
     *         in: body
     *         required: true
     *         schema:
     *           type: array
     *           items:
     *             type: object
     *             properties:
     *               userId:
     *                 type: number
     *               status:
     *                 type: number
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: Users status updated Successfully
     * 
     */

    public updateUsersStatus(): any {
        return [
            authenticateJWT,
            this.userManagementValidation.userIdValidation(),
            async (request: Request, response: Response) => {
                try {
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {

                        userModel.updateUsersStatus(request, function (error: boolean) {

                            if (!error) {
                                return apiResponse.successResponse(response, "USER0005");
                            }

                            return apiResponse.unauthorizedResponse(response, "GEN0007");
                        })

                    }

                } catch (err) {
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }
        ]
    }



    /**
     * @swagger
     * /users/is-user-exist:
     *   post:
     *     tags:
     *       - UserManagementController
     *     description:
     *       user exist checking Api
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: body
     *         description: user exist checking Api
     *         in: body
     *         required: true
     *         schema:
     *           type: object
     *           required:
     *             - email
     *           properties:
     *             email:
     *               type: string
     *       - name: token
     *         in: header
     *         type: string
     *         required: true
     *     responses:
     *       200:
     *         description: User is not exist
     * 
     */

    public isUserExist(): any {
        return [
            authenticateJWT,
            this.userManagementValidation.isUserExist(),
            async (request: Request, response: Response) => {
                try {
                    // Extract the validation errors from a request.
                    const errors = validationResult(request);
                    if (!errors.isEmpty()) {
                        // Display sanitized values/errors messages.
                        return apiResponse.validationErrorWithData(response, "GEN0003", errors.array());
                    } else {

                        let email = request.body.email;

                        userModel.isUserExist(email, function (error) {
                            if (!error) {
                                return apiResponse.successResponse(response, "USER0006");
                            }
  
                            return apiResponse.unauthorizedResponse(response, "USER0007");
                        })
  
  
                    }
                } catch (error) {
                    //throw error in json response with status 500.
                    return apiResponse.ErrorResponse(response, "GEN0004");
                }
            }
        ]
    }
}

export default userManagementController