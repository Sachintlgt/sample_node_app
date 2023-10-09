import { Request, Response } from 'express';
import { DataTypes, Op,Sequelize } from 'sequelize';
import * as bcrypt from 'bcrypt';
import * as _ from  'lodash';
import * as randomstring from 'randomstring';
import * as moment from 'moment';
import db from '../helpers/databaseConfig';
import { Registration, Login, UpdatePassword, CreateUser, UpdateProfile, updateUserStatus } from '../interface/auth';
import roleModel from './roleModel';
import emailTemplate from "../helpers/template";
import {createLog} from "./loggerModel"

class UserModel {

	private company;
	private users;
	private usersProfiles;
	private usersRoles;
	private roles;

	constructor() {
		this.company = db.define("company", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			name: {
				type: DataTypes.STRING,
				allowNull: false
			},
			status: {
				type: DataTypes.INTEGER,
				allowNull: false,
				defaultValue: 1
			},
			created_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			created_by: {
				type: DataTypes.INTEGER,
				allowNull: false,
			},
			updated_at: {
				type: DataTypes.DATE
			},
			updated_by: {
				type: DataTypes.INTEGER,
			},
		}, {
				timestamps: false,
				freezeTableName: true,
		});

		this.users = db.define("users", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			email: {
				type: DataTypes.STRING,
				allowNull: false
			},
			first_name: {
				type: DataTypes.STRING,
				allowNull: false
			},
			last_name: {
				type: DataTypes.STRING
			},
			password: {
				type: DataTypes.STRING,
				allowNull: false
			},
			status: {
				type: DataTypes.INTEGER,
				allowNull: false,
				defaultValue: 0
			},
			created_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			created_by: {
				type: DataTypes.INTEGER,
				allowNull: false,
			},
			updated_at: {
				type: DataTypes.DATE
			},
			updated_by: {
				type: DataTypes.INTEGER,
			},
			company_id: {
				type: DataTypes.INTEGER,
				allowNull: true,
			},
			product_categories:{
				type: DataTypes.STRING
			}
		}, {
				timestamps: false
		});

		this.usersRoles = db.define("users_roles", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			user_id: {
				type: DataTypes.INTEGER,
				allowNull: false
			},
			role_id: {
				type: DataTypes.INTEGER,
				allowNull: false
			},
			created_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			created_by: {
				type: DataTypes.INTEGER,
				allowNull: false,
			},
			updated_at: {
				type: DataTypes.DATE
			},
			updated_by: {
				type: DataTypes.INTEGER,
			},
		}, {
				timestamps: false
		});

		this.roles = db.define("roles", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			name: {
				type: DataTypes.STRING
			},
			status: {
				type: DataTypes.INTEGER
			},
			created_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			created_by: {
				type: DataTypes.INTEGER,
				allowNull: false,
			},
			updated_at: {
				type: DataTypes.DATE
			},
			updated_by: {
				type: DataTypes.INTEGER,
			},
		}, {
				timestamps: false
		});

		this.usersProfiles = db.define("users_profiles", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			user_id: {
				type: DataTypes.INTEGER,
				allowNull: false
			},
			profile_image: {
				type: DataTypes.STRING
			},
			avatar: {
				type: DataTypes.STRING
			},
			country_code: {
				type: DataTypes.INTEGER
			},
			phone: {
				type: DataTypes.INTEGER,
			},
			address: {
				type: DataTypes.STRING
			},
			created_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			created_by: {
				type: DataTypes.INTEGER,
				allowNull: false,
			},
			updated_at: {
				type: DataTypes.DATE
			},
			updated_by: {
				type: DataTypes.INTEGER,
			},
		}, {
				timestamps: false
		});

		this.users.hasOne(this.usersProfiles,{as:'usersProfiles',foreignKey: 'user_id'});

		this.users.belongsTo(this.company, { foreignKey: "company_id" });

		this.usersRoles.hasOne(this.roles, { as: 'roles', foreignKey: 'id' , sourceKey: 'role_id' });

	}

	public async emailIsExist(email: string, withStatus: boolean, callback: Function): Promise<any> {
		try {
			let queryObject: {[key: string] : any} = { email: email };

			if (withStatus) {
				queryObject.status = 1
			}
			
			let userData = await this.users.findOne({
				where: queryObject
			})

			return callback(userData ? null: 'Not found', userData);

		} catch (error) {
			return callback(error, null)
		}
	}

	public async registration(userData: Registration, callback: Function): Promise<any> {
		try {
			let error = true;
			userData.password = await bcrypt.hashSync(userData.password, 10);
			const data = await this.users.create({ first_name: userData.firstName, last_name: userData.lastName, email: userData.email, password: userData.password, status: userData.status, created_at: userData.createdAt, created_by: userData.createdBy });
			if (data.id) {
				roleModel.userMapWithRole({ userId: data.id, roleId: parseInt(process.env.DEFAULT_ROLE_ID) }, function (err, code) {

					if (!err) {
						error = false;
					}
					return callback(error);
				})

			} else {
				return callback(error);
			}
		} catch (error) {
			createLog(error, 'registration', { "userData": userData }, "userModel");
			return callback(true);
		}
	}

	public async login(userData: Login, request: Request, callback: Function): Promise<any> {
		try {
			let userSet = {};
			let userDetail = await this.users.findOne({ 
				attributes: [
					'id',
					'email',
					'first_name',
					'last_name',
					'password',
					[Sequelize.col('usersProfiles.country_code'), 'country_code'],
					[Sequelize.col('usersProfiles.phone'),'phone'],
					[Sequelize.col('usersProfiles.address'), 'address'],
					[Sequelize.col('usersProfiles.avatar'), 'avatar'],
					[Sequelize.col('usersProfiles.profile_image'), 'profile_image']
				],
				include: [{
					model: this.usersProfiles,
					as:"usersProfiles",
					attributes:[],
					required:false
				}],
				order:[
					["id", "DESC"]
				],				
				where: { email: userData.email, status: 1 } 
			});

			if (userDetail === null) {
				return callback(true, "AUTH0005", null);
			}
			userDetail = JSON.parse(JSON.stringify(userDetail));
			if (!bcrypt.compareSync(userData.password, userDetail.password)) {
				callback(true, "AUTH0006", null);
			} else {
				let roleIds = []
				let userRoleList = [];
				roleModel.findRoleNameId(userDetail.id, async function (roleSet) {
					let domain = request.headers.origin.toString();
					console.log(domain);
					if (roleSet.rolesArr.length == 1 && roleSet.rolesArr.includes(parseInt(process.env.DEFAULT_ROLE_ID)) && domain.includes("fa.charaka")) {
						return callback(true, 'GEN0005', null);
					}

					// if (roleSet.rolesArr.includes(parseInt(process.env.DEFAULT_ROLE_ID))) {
					// 	return callback(true, 'AUTH0003', null);
					// }
					
					roleIds = roleSet.rolesArr;
					userRoleList = roleSet.rolesNameArr;

					userSet = {
						id: userDetail.id,
						email: userDetail.email,
						firstName: userDetail.first_name,
						lastName: userDetail.last_name,
						countryCode: userDetail.country_code,
						phone: userDetail.phone,
						address: userDetail.address,
						avatar: userDetail.avatar,  //remove after getting user profile image
						profileImage: userDetail.profile_image,
						roleIds: roleIds,
						userRole: userRoleList
					}
					return callback(false, null, userSet);
				})

			}

		} catch (error) {
			console.log(error);
			createLog(error, 'login', { "userData": userData }, "userModel");
			return callback(true, 'GEN0007', error);
		}
	}

	public async passwordValidation(email: string, password: string, callback: Function): Promise<any> {
		try {

			let userDetail = await this.users.findOne({ where: { email: email } });
			if (userDetail == null) {
				return callback(true, 'VAL0004')
			}

			if (userDetail.status != 0) {
				
				if (!bcrypt.compareSync(password, userDetail.password)) {					
					callback(false, null);
				} else {
					callback(true, "VAL0010");
				}
			} else {
				return callback(true, "VAL0006")
			}

		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async passwordIsExist(userData: UpdatePassword, callback: Function): Promise<any> {
		try {
			let userDetail = await this.users.findOne({ where: { id: userData.userId } });
			if (userDetail == null) {
				return callback(true, 'VAL0004')
			}

			if (userDetail.status != 0) {
				if (!bcrypt.compareSync(userData.password, userDetail.password)) {
					callback(true, "VAL0005");
				} else {
					callback(false, null);
				}
			} else {
				return callback(true, "VAL0006")
			}

		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async updatePassword(userData: UpdatePassword, callback: Function): Promise<any> {
		try {
			userData.password = await bcrypt.hashSync(userData.password, 10);
			let userDetailUpdated = await this.users.update({ password: userData.password }, {
				where: {
					id: userData.userId
				}
			});

			if (userDetailUpdated) {
				return callback(false, "AUTH0009");
			}
			return callback(true, "GEN0004");

		} catch (error) {
			createLog(error, 'updatePassword', { "userData": userData }, "userModel");
			return callback(true, "GEN0004")
		}
	}

	public async updateProfile(userData: UpdateProfile, callback: Function): Promise<any> {
		try {
			let userAlreadyExist = await this.usersProfiles.findOne({ where: { user_id: userData.userId } });
			if (userAlreadyExist === null) {
				let userSet: { [k: string]: any } = {};
				userSet.user_id = userData.userId;
				if (userData.phone) {
					userSet.phone = userData.phone;
				}
				if (userData.address) {
					userSet.address = userData.address;
				}
				if (userData.avatar) {
					userSet.avatar = userData.avatar;
				}
				userSet.created_at = userData.updatedAt;
				userSet.created_by = userData.updatedBy;
				userSet.updated_at = userData.updatedAt;
				userSet.updated_by = userData.updatedBy;

				await this.usersProfiles.create(userSet);
			} else {
				let userSet: { [k: string]: any } = {};
				if (userData.phone !== null) {
					userSet.phone = userData.phone;
				}
				if (userData.address !== null) {
					userSet.address = userData.address;
				}
				if (userData.avatar !== null) {
					userSet.avatar = userData.avatar;
				}
				userSet.updated_at = userData.updatedAt;
				userSet.updated_by = userData.updatedBy;
				
				await this.usersProfiles.update(userSet, {
					where: {
						user_id: userData.userId
					}
				});
			}
			let userSetUpdate: { [k: string]: any } = {};

			if(userData.firstName){
				userSetUpdate.first_name = userData.firstName;
			}
			
			if(userData.lastName !== null){
				userSetUpdate.last_name = userData.lastName;
			}

			if(userData.status !== null){
				userSetUpdate.status = userData.status;
			}
			if(userData.companyId !== null){
				userSetUpdate.company_id = userData.status;
			}
			if(userData.productCategories !== null){
				userSetUpdate.product_categories = userData.productCategories;
			}
			if (userData.email && userData.email !== null) {
				let userEmailExists = await this.users.findOne({
					where: {
						[Op.and]: [{
							id: {
								[Op.ne]: userData.userId
							},
							email: userData.email,
						}
						]
					}, attributes: ['email']
				});
				if (userEmailExists == null) {
					userSetUpdate.email = userData.email;
				} else return callback('true', 'VAL0001')

			}
			if (!_.isEmpty(userSetUpdate)){
				userSetUpdate.updated_at = userData.updatedAt;
				userSetUpdate.updated_by = userData.updatedBy;
				await this.users.update(userSetUpdate, {
					where: {
						id: userData.userId
					}
				});
			}
			if(userData.roles && userData.roles.length){
				
				let roleSet=[];
				await this.usersRoles.destroy({
					where:{user_id:userData.userId}
				});
				userData.roles.forEach(element => {
					roleSet.push({
						user_id: userData.userId,
						role_id: element
					});
				});
				await this.usersRoles.bulkCreate(roleSet);
			}

			callback(false, "AUTH0010");

		} catch (error) {
			console.log(error);
			createLog(error, 'updateProfile', { "userData": userData }, "userModel");
			return callback(true, "GEN0004")
		}
	}

	public async createUser(userData: CreateUser, callback: Function): Promise<any> {
		try {
			let error = true;
			let userDataSet: {[key: string]: any} = {};
			let userProfileDataSet: {[key: string]: any} = {};
			let randomPass = randomstring.generate({ length: 6, charset: 'alphabetic' });
			let password = await bcrypt.hashSync(randomPass, 10);
			let userName = `${userData.firstName}${userData.lastName ? " " + userData.lastName: ""}`;

			userDataSet.email = userData.email;
			userDataSet.first_name = userData.firstName;
			userDataSet.status = userData.status;
			userDataSet.password = password;
			userDataSet.company_id =userData.companyId;
			userDataSet.product_categories =userData.productCategories;
			userData.lastName ? userDataSet.last_name = userData.lastName : null;
			userData.createdBy ? userDataSet.created_by = userData.createdBy : null;

			let userDetail = await this.users.create(userDataSet);
			
			if(userDetail === null){
				return callback(error);		
			}

			let templateKeys: {[key:string]: any} = {
				APP_NAME: userData.roleIds.includes(process.env.USERS_ROLES_USERS) ? process.env.USER_APP_NAME : process.env.ADMIN_APP_NAME,
				NAME: userName,
				EMAIL_ADDRESS: userData.email,
				PASSWORD: randomPass,
				LOGIN_URL: process.env.LOGIN_APP_URL
			};

			let subjectKeys: {[key:string]: any} = {};

			console.log("templateKeys", templateKeys);
			
			emailTemplate.sendEmailTemplate(process.env.CREATE_USER_EMAIL_TEMPLATE_ID, userDataSet.email, subjectKeys, templateKeys, (err) => {
			});

			error = false;
			userData.phone ? userProfileDataSet.phone = userData.phone : null;
			userData.address ? userProfileDataSet.address = userData.address : null;
			userData.avatar ? userProfileDataSet.avatar = userData.avatar : null;

			if(Object.keys(userProfileDataSet).length){
				userData.createdBy ? userProfileDataSet.created_by = userData.createdBy : null;
				userProfileDataSet.user_id = userDetail.id;
				await this.usersProfiles.create(userProfileDataSet);
			}

			if(!userData.roleIds || userData.roleIds.length == 0){
				userData.roleIds = [process.env.DEFAULT_ROLE_ID];
			}

			let roleSet=[];
			userData.roleIds.forEach(element => {
				roleSet.push({
					user_id: userDetail.id,
					role_id: element
				});
			});
			await this.usersRoles.bulkCreate(roleSet);

			
			return callback(error);

		} catch (error) {
			console.log(error);
			createLog(error, 'createUser', { "userData": userData }, "userModel");
			return callback(true);
		}
	}


	public async updateUserStatus(userData: updateUserStatus, callback: Function): Promise<any> {
		try {
			let userStatusUpdated = await this.users.update({ status: userData.statusId }, {
				where: {
					id: userData.userId
				}
			});

			if (userStatusUpdated) {
				return callback(false, "AUTH0011");
			}
			return callback(true, "GEN0004");

		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async deleteUser(userId: number, callback: Function): Promise<any> {
		try {
			let userStatusUpdated = await this.users.update({ status: process.env.DELETE_USER_STATUS_ID }, {
				where: {
					id: userId
				}
			});

			if (userStatusUpdated) {
				return callback(false, "AUTH0011");
			}
			return callback(true, "GEN0004");

		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async userIsExist(userId: number, callback: Function): Promise<any> {
		try {
			let check = false;

			let userData = await this.users.findOne({
				where: { id: userId }
			})
			
			if (userData === null) {
				check = true;
			}
			return callback(check, null)

		} catch (error) {
			
			return callback(true, error)
		}
	}

	public async getUserDetail(userId: number, callback: Function): Promise<any> {
		try {
			let userSet = {};
			let userData = await this.users.findOne({ 
				attributes: [
					'id',
					'email',
					'first_name',
					'last_name',
					'password',
					'status',
					'comapnyId',
					'productCategories'
					[Sequelize.col('usersProfiles.phone'),'phone'],
					[Sequelize.col('usersProfiles.address'), 'address'],
					[Sequelize.col('usersProfiles.avatar'), 'avatar']
				],
				include: [{
					model: this.usersProfiles,
					as:"usersProfiles",
					attributes:[],
					required:false
				}],
				order:[
					["id", "DESC"]
				],				
				where: { id: userId} 
			});

			userData = JSON.parse(JSON.stringify(userData));
			
			if (userData !== null) {
				roleModel.findRoleId(userId, function (roleIdList) {
					userSet = {
						id: userData.id,
						email: userData.email,
						firstName: userData.first_name,
						lastName: userData.last_name,
						phone: userData.phone,
						address: userData.address,
						avatar: userData.avatar,  //remove after getting user profile image
						status: userData.status,  //remove after getting user profile image
						roleIds: roleIdList
					}
					return callback(false, userSet,"AUTH0013");
				});
			}else{
				return callback(true, userSet,"GEN0007")
			}

		} catch (error) {
			console.log(error);
			
			return callback(true, null,"GEN0004")
		}
	}

	public async getUserList(callback: Function): Promise<any> {
		try {
			let check = false;
			
			let userData = await this.users.findAll({
				attributes: ["id","email",["first_name","firstName"],["last_name","lastName"],"status",[Sequelize.col('users_profiles.phone'), 'phone'],[Sequelize.col('users_profiles.address'), 'address']],
				include: [{
					model: this.usersProfiles,
					attributes:[],
					required:false
				}]
			});

			userData = JSON.parse(JSON.stringify(userData));
			
			if (userData === null) {
				check = true;
			}
			return callback(check, userData,"AUTH0013")

		} catch (error) {
			
			return callback(true, null,"GEN0004")
		}
	}

	public async updateUserProfile(userData: UpdateProfile, callback: Function): Promise<any> {
		try {
			let userAlreadyExist = await this.usersProfiles.findOne({ where: { user_id: userData.userId } });
			if (userAlreadyExist === null) {
				let userSet: { [k: string]: any } = {};
				userSet.user_id = userData.userId;
				userSet.country_code = userData.countryCode;
				userSet.phone = userData.phone;
				if (userData.address) {
					userSet.address = userData.address;
				}
				if (userData.avatar) {
					userSet.profile_image = userData.avatar;
				}
				userSet.created_by = userData.updatedBy;
				userSet.updated_by = userData.updatedBy;

				await this.usersProfiles.create(userSet);
			} else {
				let userSet: { [k: string]: any } = {};
				userSet.phone = userData.phone;
				userSet.country_code = userData.countryCode;
				if (userData.address) {
					userSet.address = userData.address;
				}
				if (userData.avatar) {
					userSet.profile_image = userData.avatar;
				}
				userSet.updated_by = userData.updatedBy;

				await this.usersProfiles.update(userSet, {
					where: {
						user_id: userData.userId
					}
				});
			}
			let userSetUpdate: { [k: string]: any } = {};

			if(userData.firstName){
				userSetUpdate.first_name = userData.firstName;
			}

			if(userData.lastName){
				userSetUpdate.last_name = userData.lastName;
			}

			if (Object.keys(userSetUpdate).length > 0) {
				userSetUpdate.updated_by = userData.updatedBy;

				await this.users.update(userSetUpdate, {
					where: {
						id: userData.userId
					}
				});
			}
			const data = await this.users.findOne({
				where: { id: userData.userId },
				attributes: ["id", "email", ["first_name", "firstName"], ["last_name", "lastName"], "status", [Sequelize.col('usersProfiles.country_code'), 'countryCode'], [Sequelize.col('usersProfiles.phone'), 'phone'], [Sequelize.col('usersProfiles.address'), 'address'], [Sequelize.col('usersProfiles.profile_image'), 'profileImage']],
				include: [{
					model: this.usersProfiles,
					as: "usersProfiles",
					attributes: [],
					required: true
				}]
			});
			if (data === null) {
				return callback(true, "VAL0004", null);
			}
			return callback(false, "AUTH0010", data);
		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async getUserDetailWithProfileImage(userId: number, callback: Function): Promise<any> {
		try {
			let check = false;
			
			let userData = await this.users.findOne({
				where: { id: userId },
				attributes: ["id", "email", ["first_name", "firstName"], ["last_name", "lastName"], "status", [Sequelize.col('usersProfiles.country_code'), 'countryCode'], [Sequelize.col('usersProfiles.phone'), 'phone'], [Sequelize.col('usersProfiles.address'), 'address'], [Sequelize.col('usersProfiles.avatar'), 'avatar']],
				include: [{
					model: this.usersProfiles,
					as: "usersProfiles",
					attributes:[],
					required:true
				}]
			});

			userData = JSON.parse(JSON.stringify(userData));
			
			if (userData === null) {
				check = true;
			}
			return callback(check, userData,"AUTH0013")

		} catch (error) {	
			return callback(true, null,"GEN0004")
		}
	}


	public async getUserRoleCount(callback: Function): Promise<any> {
		try {

			let usersRolesCount = await this.usersRoles.findAll({
				attributes: [
					['role_id', 'roleId'],
					[Sequelize.col('roles.name'), 'roleName'],
					[Sequelize.fn("COUNT", "users_roles.id"), "count"]
				],
				include: [{
					model: this.roles,
					as: "roles",
					attributes: [],
					required: true
				}],
				group: ['users_roles.role_id']
			});
			const totalCount = await this.usersRoles.count();


			usersRolesCount = JSON.parse(JSON.stringify(usersRolesCount));

			usersRolesCount.forEach(data => {
				data.percentage = ((data.count / totalCount) * 100).toFixed(2);
			});

			return callback(false, usersRolesCount, "USER0001")

		} catch (error) {
			console.log(error);

			return callback(true, null, "GEN0004")
		}
	}

	public async getUserFilterList(callback: Function): Promise<any> {
		try {
			let check = false;
			let filterOptionsMap: { [k: string]: any } = {};

				filterOptionsMap.currentStatus = { options: [
					{
						value: 0,
						label: "Inactive"
					},
					{
						value: 1,
						label: "Active"
					},
					{
						value: 2,
						label: "Deleted"
					}
				] }

			let roles = await this.roles.findAll({
				attributes: [
					["id", 'value'],
					["name", "label"],
				]
			});

			roles = JSON.parse(JSON.stringify(roles));

			if (roles !== null) {
				filterOptionsMap.role = { options: roles }
			}

			let lastUpdatedBy = await this.users.findAll({
				attributes: [
					[Sequelize.fn('DISTINCT', Sequelize.col('id')), 'value'],				
					[Sequelize.fn("CONCAT", Sequelize.fn('COALESCE', Sequelize.col('users.first_name'), ""), " ", Sequelize.fn('COALESCE', Sequelize.col('users.last_name'), "")), "label"],
				],
				where:{
					updated_by:{
					  [Op.not]: null
					} 
				}
			});

			lastUpdatedBy = JSON.parse(JSON.stringify(lastUpdatedBy));

			if (lastUpdatedBy !== null) {
				filterOptionsMap.lastUpdatedBy = { options: lastUpdatedBy }
			}


			return callback(check, { filterOptionsMap }, "USER0002")

		} catch (error) {
			console.log(error);

			return callback(true, null, "GEN0007")
		}
	}

	public async getUserRolesList(callback: Function): Promise<any> {
		try {

			let rolesData = await this.roles.findAll({
				attributes:[
					["id","value"],
					["name","label"]
				]
			});

			rolesData = JSON.parse(JSON.stringify(rolesData));

			return callback(false, rolesData)

		} catch (error) {
			console.log(error);

			return callback(true, error)
		}
	}

	public async getUsersList(request: Request, callback: Function): Promise<any> {
		try {
			let limit = request.body.limit ? request.body.limit : parseInt(process.env.DEFAULT_RECORDS_LIMIT);
			let page = request.body.page || 1;
			let offset = 0 + (page - 1) * limit
			let condition: { [k: string]: any } = {};

			let status = ["Inactive","Active","Deleted"];

			let sortingSet = ["id", "DESC"];
			if (request.body.sortKey && request.body.sortOrder) {
				if (request.body.sortKey == "name") {
					sortingSet = ["first_name", request.body.sortOrder];
				}

				if (request.body.sortKey == "email") {
					sortingSet = ["email", request.body.sortOrder];
				}

				if (request.body.sortKey == "currentStatus") {
					sortingSet = ["status", request.body.sortOrder];
				}

				if (request.body.sortKey == "lastUpdatedBy") {
					sortingSet = ["updated_by", request.body.sortOrder];
				}

				// if (request.body.sortKey == "role") {
				// 	sortingSet = ["users_roles.role_id", request.body.sortOrder];
				// }

			}

			let usersDetail = await this.users.findAll({
				attributes: [
					'id',
					'email',
					'first_name',
					'last_name',
					'created_at',
					'updated_at',
					[Sequelize.col('usersProfiles.phone'), 'phone'],
					[Sequelize.col('usersProfiles.address'), 'address'],
					[Sequelize.col('usersProfiles.avatar'), 'avatar']
				],
				include: [{
					model: this.usersProfiles,
					as: "usersProfiles",
					attributes: [],
					required: false
				}]
			});
			let userObj = {};

			usersDetail = JSON.parse(JSON.stringify(usersDetail));

			usersDetail.forEach(data => {
				userObj[data.id] = data
			})

			let usersRoles = await this.usersRoles.findAll({
				attributes: [
					['user_id', 'userId'],
					['role_id', 'roleId'],
					[Sequelize.col('roles.name'), 'roleName']
				],
				include: [{
					model: this.roles,
					as: "roles",
					attributes: [],
					required: true
				}]
			});

			usersRoles = JSON.parse(JSON.stringify(usersRoles));
			let usersRolesSet = {};

			usersRoles.forEach(element => {
				if(!usersRolesSet[element.userId]){
					usersRolesSet[element.userId]= [];
				}
				usersRolesSet[element.userId].push(element.roleName);
			});


			condition = {
				attributes: [
					["id", "userId"],
					[Sequelize.fn("CONCAT", Sequelize.fn('COALESCE', Sequelize.col('users.first_name'), ""), " ", Sequelize.fn('COALESCE', Sequelize.col('users.last_name'), "")), "name"],
					["email", "email"],
					["status", "currentStatus"],
					['created_by', 'createdBy'],
					['created_at', 'createdAt'],
					['updated_by', 'updatedBy'],
					['updated_at', 'updatedAt'],
					[Sequelize.col('usersProfiles.phone'), 'phoneNo']
				],
				include: [{
					model: this.usersProfiles,
					as: 'usersProfiles',
					attributes: [],
					required: false
				}],
				offset: offset,
				limit: parseInt(limit),
				order: [
					sortingSet
				]
			};

			let userWhereCondition: { [k: string]: any } = {}
			let conditionCheck = false;

			if (request.body.searchColumnList && request.body.searchString) {
				let tempArSet = []
				request.body.searchColumnList.forEach(columnName => {

					if (columnName == "name") {
						tempArSet.push({
							first_name:{
								[Op.like]: "%" + request.body.searchString + "%"
							}
						})
						tempArSet.push({
							last_name:{
								[Op.like]: "%" + request.body.searchString + "%"
							}
						})
							
					}

					if (columnName == "email") {
						tempArSet.push({
							email:{
								[Op.like]: "%" + request.body.searchString + "%"
							}
						})
					}
					
				})
				if (tempArSet.length) {
					conditionCheck = true;
					userWhereCondition = { [Op.or]: tempArSet };
				}
			}


			if (request.body.currentStatus !== null && request.body.currentStatus !== undefined) {
				userWhereCondition.status = request.body.currentStatus
			}


			if (request.body.role) {
				let userIdSet = [];
				let usersRolesCheck = await this.usersRoles.findAll({
					attributes: [
						['user_id', 'userId']
					],
					where:{role_id:request.body.role}
				});
				usersRolesCheck = JSON.parse(JSON.stringify(usersRolesCheck));
				usersRolesCheck.forEach(element => {
					userIdSet.push(element.userId);
				});

				userWhereCondition.id = {
					[Op.in]: userIdSet
				}
			}

			if (request.body.lastUpdatedBy) {
				userWhereCondition.updated_by= request.body.lastUpdatedBy;
			}

			if (request.body.lastUpdatedPeriod) {
				request.body.lastUpdatedPeriod = request.body.lastUpdatedPeriod.split("-");
				if (request.body.lastUpdatedPeriod[0] && request.body.lastUpdatedPeriod[1]) {
					userWhereCondition.updated_at = {
						[Op.gte]: moment(new Date(+request.body.lastUpdatedPeriod[0])).format("YYYY-MM-DD") + " 00:00:00",
						[Op.lte]: moment(new Date(+request.body.lastUpdatedPeriod[1])).format("YYYY-MM-DD") + " 23:59:59"
					};
				}
			}

			if (request.body.createdPeriod) {
				request.body.createdPeriod = request.body.createdPeriod.split("-");
				if (request.body.createdPeriod[0] && request.body.createdPeriod[1]) {
					userWhereCondition.created_at = {
						[Op.gte]: moment(new Date(+request.body.createdPeriod[0])).format("YYYY-MM-DD") + " 00:00:00",
						[Op.lte]: moment(new Date(+request.body.createdPeriod[1])).format("YYYY-MM-DD") + " 23:59:59"
					};
				}
			}

			if (Object.keys(userWhereCondition).length || conditionCheck) {
				condition.where = userWhereCondition;
			}


			// console.log("condition ==>",JSON.stringify(condition));

			let usersData = await this.users.findAll(condition);

			delete condition.attributes;
			delete condition.offset;
			delete condition.limit;
			delete condition.order;

			let usersCount = await this.users.count(condition);

			usersData = JSON.parse(JSON.stringify(usersData));
			// console.log("plantsData ==>",usersData);

			let tempData: { [k: string]: any } = {}
			tempData.page = page;
			tempData.totalResultCount = usersCount;
			tempData.rowList = [];

			usersData.forEach(dataSet => {
				let data: { [k: string]: any } = {}

				data.name = {
					label: dataSet.name
				}

				data.email = {
					label: dataSet.email
				}

				data.currentStatus = {
					label: status[dataSet.currentStatus] ? status[dataSet.currentStatus]: null
				}

				data.phoneNo = {
					label: dataSet.phoneNo
				}
				
				data.role = {
					label: usersRolesSet[dataSet.userId] ? usersRolesSet[dataSet.userId].join(", ") : null,
				}

				data.lastUpdatedBy = {
					label: userObj[dataSet.updatedBy] ? (userObj[dataSet.updatedBy].first_name) + (userObj[dataSet.updatedBy].last_name ? " " + userObj[dataSet.updatedBy].last_name : "") : null,
					date: dataSet.updatedAt ? moment(dataSet.updatedAt).format("x") : dataSet.updatedAt,
					avatar: userObj[dataSet.updatedBy] && userObj[dataSet.updatedBy].avatar ? userObj[dataSet.updatedBy].avatar : null,
				}

				data.createdBy = {
					label: userObj[dataSet.createdBy] ? (userObj[dataSet.createdBy].first_name) + (userObj[dataSet.createdBy].last_name ? " " + userObj[dataSet.createdBy].last_name : "") : null,
					date: dataSet.createdAt ? moment(dataSet.createdAt).format("x") : dataSet.createdAt,
					avatar: userObj[dataSet.createdBy] && userObj[dataSet.createdBy].avatar ? userObj[dataSet.createdBy].avatar : null,
				}

				tempData.rowList.push({
					id: dataSet.userId,
					data: data
				});
			})

			return callback(false, tempData)


		} catch (error) {
			console.log(error);

			return callback(true, error)
		}
	}

	public async updateUsersStatus(request: Request, callback: Function): Promise<any> {
		try {
			
			request.body.forEach(async (element) => {
				await this.users.update({ status: element.status }, {
					where: {
						id: element.userId
					}
				});
			});

			return callback(false);

		} catch (error) {
			return callback(true, "GEN0004")
		}
	}

	public async isUserExist(email: string, callback: Function): Promise<any> {
		try {
			let queryObject = { email: email };

			let userData = await this.users.findOne({
				where: queryObject
			})

			if(userData === null){
				return callback(false)
			}
			return callback(true)

		} catch (error) {
			return callback(error, null)
		}
	}
}
export default new UserModel();
