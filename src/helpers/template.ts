import { DataTypes, Op, Sequelize } from 'sequelize';
import db from '../helpers/databaseConfig';
import * as mailer from "../helpers/mailer";


class Template{

    public emailTemplates;

    constructor(){

        this.emailTemplates = db.define("email_templates", {
			id: {
				type: DataTypes.INTEGER,
				allowNull: false,
				autoIncrement: true,
				primaryKey: true
			},
			name: {
				type: DataTypes.STRING
            },
            subject: {
				type: DataTypes.STRING
            },
            content: {
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
        
    }

    public async sendEmailTemplate(templateId, userEmail, subjectKeys, bodyKeys, callback: Function): Promise<any> {
        try{
            
            let templateDetail = await this.emailTemplates.findOne({
                where:{
                    id: templateId,
                    status: 1
                }
            });

            if(templateDetail === null){
                return callback(true);
            }

            templateDetail = JSON.parse(JSON.stringify(templateDetail));

            for (const key in subjectKeys) {
                templateDetail.subject = templateDetail.subject.replace(`{{${key}}}`,subjectKeys[key]);
            }

            for (const key in bodyKeys) {
                templateDetail.content = templateDetail.content.replace(`{{${key}}}`,bodyKeys[key]);
            }

            console.log("email ==> ",process.env.EMAIL_ADDRESS, userEmail, templateDetail.subject, templateDetail.content);

            mailer.send(process.env.EMAIL_ADDRESS, userEmail, templateDetail.subject, templateDetail.content, (err, result) => {
                return callback(!err ? false : true);
			});

        }catch(error){
             console.log(error);
             
            return callback(true);
        }
    }
}

export default new Template();