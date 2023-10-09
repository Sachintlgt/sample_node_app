import { Request, Response } from 'express';
import * as multer from 'multer';
import * as mime from 'mime';
import * as fs from 'fs';
import * as randomstring from 'randomstring';
import * as path from 'path';
import * as async from 'async';
import * as gm from 'gm';
import * as sizeOf from 'image-size'
import * as aws from 'aws-sdk';
gm.subClass({ imageMagick: true });
class S3 {

    private bucket: string;

    constructor(){
        this.bucket= process.env.S3_BUCKET;
        aws.config.update({
            secretAccessKey: process.env.SECRET_ACCESS_KEY,
            accessKeyId: process.env.ACCESS_KEY_ID,
            region: 'us-west-2'
        });
    }

    private fileValidation(file, extType){
        let extensionList = {
            images: ['png', 'jpg', 'jpeg', 'tif', 'webp'],
            docs: ['doc', 'docx', 'odt', 'pdf', 'rtf', 'tex', 'txt', 'wks', 'wps', 'wpd', 'xlsm', 'xlsx', 'xlt'],
            pdf: ['pdf'],
            file: ['png', 'jpg', 'jpeg', 'tif', 'doc', 'docx', 'odt', 'pdf', 'rtf', 'tex', 'txt', 'wks', 'wps', 'wpd', 'xlsm', 'csv', 'xls', 'xlsx', 'xlt'],
            csv: ['csv', 'xls', 'xlsx'],
            bulkImgDocs: ['zip', 'rar'],
            bulkDocs: ['zip', 'pdf'],
            imgDoc: ['png', 'jpg', 'jpeg', 'tif', 'doc', 'docx', 'odt', 'pdf', 'rtf', 'tex', 'txt'],
            imgVid: ['png', 'jpg', 'jpeg', 'tif', 'avi', 'flv', 'wmv', 'mp4', 'mov', '3gp'], //'asf', 'rm', 'mpg','swf'
            video: ['avi', 'flv', 'wmv', 'mp4', 'mov', '3gp', 'mpg', 'asf', 'rm', 'swf'],

        }
        
        var ext = mime.getExtension(file.mimetype).toLowerCase();

        if (extensionList[extType] && extensionList[extType].indexOf(ext) == -1) {
            return { error: true, msg: 'Invalid file type (' + ext + ' ' + file.mimetype + ') Only ' + extensionList[extType].join(', ') + ' extensions are allowed' };
        } else {
            return { error: false, msg: '' };
        }
    }

    public fileUploadOnLocal(folderName, subFolderName, request, response, extTypes, callback) {
        try {
            let mainThis = this;
            var storage = multer.diskStorage({
                destination: function (request, file, callback) {
                    var root = './uploads';
                    if (!fs.existsSync(root)) {
                        fs.mkdirSync(root);
                    }
                    var dir = root + '/' + folderName + '/';
                    if (!fs.existsSync(dir)) {
                        fs.mkdirSync(dir);
                    }
                    dir = root + '/' + folderName + '/original/';
                    if (!fs.existsSync(dir)) {
                        fs.mkdirSync(dir);
                    }
                    dir = root + '/' + folderName + '/original/' + subFolderName + '/';
                    if (!fs.existsSync(dir)) {
                        fs.mkdirSync(dir);
                    }
                    callback(null, dir);
                },
                filename: function (req, file, callback) {
                    var convFileName = Date.now() + randomstring.generate({ length: 4, charset: 'alphabetic' }) + path.extname(file.originalname);
                    if (file.originalname.toLowerCase().indexOf(process.env.BULK_DEFAULT_IMAGE_NAME) != -1) {
                        convFileName = Date.now() + randomstring.generate({ length: 4, charset: 'alphabetic' }) + 'default' + path.extname(file.originalname);
                    }
                    callback(null, convFileName);
                }
            });

            var upload = multer({
                storage: storage,
                fileFilter: function (request, file, callback) {
                    var response = null;
                    
                    extTypes.forEach(function (extType, index) {
                        if (response == null || (response.error != true)) {
                            response = mainThis.fileValidation(file, extType);
                        }
                    });

                    (!response || (response && response.error != true)) ? callback(null, true) : callback(response.msg, null);
                },
                limits: {
                    fileSize: (25 * 1024 * 1024)
                }
            }).any();

            upload(request, response, callback);
        } catch (e) {
            callback(e, response);
        }
    }

    private deleteLocalFiles(localFolderPath, file):any {

        if (fs.existsSync(localFolderPath + file)) {
            fs.unlinkSync(localFolderPath + file);
        }

    }

    private returnResultingData(localFolderPath, uploadedFiles, rejectedFiles, callback) {
        fs.readdir(localFolderPath, function (err, files) {
            if (files && files.length == 0) {
                if (fs.existsSync(localFolderPath)) fs.rmdirSync(localFolderPath);
                return callback(null, uploadedFiles, rejectedFiles);
            }
        });
    }

    public uploadFilesS3(folderPath, localFolderName, subFolderName, id, callback) {

        let mainThis = this;
        
        let localFolderPath = './uploads/' + localFolderName + '/' + subFolderName + '/';
        try {
            if (fs.existsSync(localFolderPath)) {
                let uploadedFiles = [],
                    rejectedFiles = [];


                async.forEachSeries(fs.readdirSync(localFolderPath), function (file, callback2) {
                    let key = (id) ? folderPath + "/" + id + "/" + file : folderPath + "/" + file;

                    const fileContent = fs.readFileSync(localFolderPath + file);
                    // Setting up S3 upload parameters
                    let params: any = {
                        Bucket: mainThis.bucket,
                        Key: key, // File name you want to save as in S3
                        Body: fileContent
                    };

                    // if(process.env.APP_ENV == "prod"){
                    //     params.ACL = 'public-read'
                    // }


                    var s3 = new aws.S3();
                    s3.upload(params, function(err, data) {
                        console.log(err,data);
                        
                        if (err) {
                            rejectedFiles.push(file);
                            mainThis.deleteLocalFiles(localFolderPath, file);
                            callback2();
                        }else{
                            uploadedFiles.push(file);
                            mainThis.deleteLocalFiles(localFolderPath, file);
                            callback2();
                        }
                        // console.log(`File uploaded successfully. ${data.Location}`);
                    });

                }, function () {
                    /* Finished the second series, now we mark the iteration of first series done */
                    mainThis.returnResultingData(localFolderPath, uploadedFiles, rejectedFiles, callback);
                });
                // fs.readdirSync(localFolderPath).forEach(function (file, index) {

                // });
            } else {
                return callback("Files stored on local folder not found. Path - "+localFolderPath,null);
            }
        } catch (error) {
            return callback(true,error);
        }

    }

    uploadFileToLocalAndSaveToS3(localFolderName, s3BucketFolder, subFolderName, request, response, extTypes, id, callback) {
        try {
            const thisRef = this;
            var root = './uploads';
            if (!fs.existsSync(root)) {
                fs.mkdirSync(root);
            }
            var dir = root + '/' + localFolderName + '/';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }
            dir = root + '/' + localFolderName + '/original/';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }
            dir = root + '/' + localFolderName + '/original/' + subFolderName + '/';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }
            for (let i = 0; i < request.files.length; i++) {
                const file = request.files[i];
                var errorObj = null;
                
                extTypes.forEach(function (extType, index) {
                    if (errorObj == null || (errorObj.error != true)) {
                        errorObj = thisRef.fileValidation(file, extType);
                    }
                });
            }
            if (errorObj == null || (errorObj.error != true)) {
                for (let i = 0; i < request.files.length; i++) {
                    const file = request.files[i]; 
                    let convFileName = Date.now() + randomstring.generate({ length: 4, charset: 'alphabetic' }) + path.extname(file.originalname);
                    if (file.originalname.toLowerCase().indexOf(process.env.BULK_DEFAULT_IMAGE_NAME) != -1) {
                        convFileName = Date.now() + randomstring.generate({ length: 4, charset: 'alphabetic' }) + 'default' + path.extname(file.originalname);
                    }
                    fs.writeFileSync(dir + convFileName, file.buffer);
                }
                thisRef.uploadFilesS3(s3BucketFolder, `${localFolderName}/original`, subFolderName, id, function (err, docName) {
                    if(err){
                      return callback(err, null);
                    }else{
                     return callback(null, docName);
                    }
                });
            } else {
                callback(errorObj.msg, null)
            }
        } catch (err) {
            return callback(err, null);
        }
    }

    public resizeImage(localFolderName: string, subFolderName: string, Rwidth: number, Rheight: number, callback: Function) {
        try{
            var localFolderPath = './uploads/' + localFolderName + '/original/' +subFolderName+"/";
            var resizeFolderPath = './uploads/' + localFolderName + '/resize/' + subFolderName+"/" ;

            var dir = './uploads';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }
            dir = './uploads/' + localFolderName;
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }

            dir = './uploads/' + localFolderName + '/resize/';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }

            dir = './uploads/' + localFolderName + '/resize/' + subFolderName;
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }

            var countResizedFiles = 0;
            if (fs.existsSync(localFolderPath)) {
                var totalFiles = fs.readdirSync(localFolderPath);
                var total = totalFiles.length;
                totalFiles.forEach(function (file) {
                    var ext = path.extname(file);
                    let imgExts = ['.png', '.PNG', '.jpg', '.jpeg', '.JPEG', '.JPG', '.tif'];
                    if (imgExts.indexOf(ext) !== -1) {
                        var dimensions = sizeOf.imageSize(localFolderPath + file);
                        
                        var width: number = dimensions.width;

                        var height: number = (width * Rheight) / Rwidth;

                        gm(localFolderPath + file).resize(width, height,"!").noProfile().write(resizeFolderPath + file, function (err) {
                            
                            if (fs.existsSync(localFolderPath + file)) {
                                fs.unlinkSync(localFolderPath + file);
                            }
                            if (!err) {
                                countResizedFiles++;
                                if (total == countResizedFiles) {
                                    return callback(err);
                                }
                            } else {
                                return callback(err);
                            }
                        });
                    }
                });
            } else {
                return callback(null);
            }
        }catch(error){
            callback(error, null);
        }
    }

    public async uploadImageToChat(fileData, chatRoomId, callback: Function) {
        let mainThis = this;

        var s3 = new aws.S3();

        let params = [];
        
        fileData.forEach((file) => {
            params.push({
                Bucket: mainThis.bucket,
                Key: process.env.CHAT_ROOM_FILES_URL + chatRoomId + '/' + randomstring.generate({ length: 6, charset: 'alphabetic' }) + file.name.replaceAll(' ', '') , // File name you want to save as in S3
                Body: file.file
            });
        
        }) 

        let imageKey = [];
        await Promise.all(params.map(
            param => {
                s3.putObject(param).promise()
                imageKey.push(param.Key);   
            }
        ))

        
        if (imageKey.length > 0) {
            return callback(false, imageKey)
        } else {
            return callback(true, null)
        }

    }

    public async uploadGroupImageToS3(chatRoomIcon, chatRoomId, fileName, callback: Function) {
        let mainThis = this;

        var s3 = new aws.S3();
        fileName = randomstring.generate({ length: 6, charset: 'alphabetic' }) + fileName;
        

        let param = {
            Bucket: mainThis.bucket,
            Key: process.env.CHAT_ROOM_FILES_URL + chatRoomId + "/" + fileName, // File name you want to save as in S3
            Body: chatRoomIcon
        }

        try {
            s3.putObject(param).promise()
        } catch {
            return callback(true, 'GEN0010', null);
        }

        if (param.Key) {
            return callback(false, null, fileName)
        } else {
            return callback(true, null)
        }

    }
}

export default new S3();
