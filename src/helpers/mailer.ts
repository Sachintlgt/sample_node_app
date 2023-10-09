import * as nodemailer from 'nodemailer';

// create reusable transporter object using the default SMTP transport
const emailSMTPHost = process.env.EMAIL_SMTP_HOST + '';
const emailSMTPPort = +process.env.EMAIL_SMTP_PORT;
let transporter = nodemailer.createTransport({
	host: emailSMTPHost,
	port: emailSMTPPort,
	//secure: process.env.EMAIL_SMTP_SECURE, // lack of ssl commented this. You can uncomment it.
	auth: {
		user: process.env.EMAIL_SMTP_USERNAME,
		pass: process.env.EMAIL_SMTP_PASSWORD
	}
});

const send = function (from, to, subject, html, callback)
{
	// send mail with defined transport object
	// visit https://nodemailer.com/ for more options
	return transporter.sendMail({
		from: from, // sender address e.g. no-reply@xyz.com or "Fred Foo 👻" <foo@example.com>
		to: to, // list of receivers e.g. bar@example.com, baz@example.com
		subject: subject, // Subject line e.g. 'Hello ✔'
		//text: text, // plain text body e.g. Hello world?
		html: html // html body e.g. '<b>Hello world?</b>'
	}, function(err, result):any {
		if(callback) {
			callback(err, result);
		}
	});
};

const sendWithAttachment = function (from, to, subject, html, filename,path,callback)
{
	// send mail with defined transport object
	// visit https://nodemailer.com/ for more options
	return transporter.sendMail({
		from: from, // sender address e.g. no-reply@xyz.com or "Fred Foo 👻" <foo@example.com>
		to: to, // list of receivers e.g. bar@example.com, baz@example.com
		subject: subject, // Subject line e.g. 'Hello ✔'
		//text: text, // plain text body e.g. Hello world?
		html: html, // html body e.g. '<b>Hello world?</b>'
		attachments:[{   // file on disk as an attachment
			filename: filename,
			path: path // stream this file
		}]
	}, function(err, result):any {
		if(callback) {
			callback(err, result);
		}
	});
};

export { send, sendWithAttachment };