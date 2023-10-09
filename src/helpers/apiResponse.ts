import responseCode from './response';

class ApiResponse {
	constructor(){

	}
	public successResponse (res, code): Promise<Response> {
		var data = {
			status: true,
			code: responseCode[code].code,
			message: responseCode[code].msg
		};
		return res.status(200).json(data);
	};
	
	public successResponseWithData (res, code, data): Promise<Response> {
		var resData = {
			status: true,
			code: responseCode[code].code,
			message: responseCode[code].msg,
			data: data
		};

		return res.status(200).json(resData);
	};
	
	public ErrorResponse (res, code): Promise<Response> {
		var data = {
			status: false,
			code: responseCode[code].code,
			message: responseCode[code].msg
		};
		return res.status(500).json(data);
	};

	public ErrorResponseWithMsg (res, code, msg): Promise<Response> {
		var data = {
			status: false,
			code: responseCode[code].code,
			message: msg
		};
		return res.status(500).json(data);
	};

	public ErrorResponseWithMsgStage (res, code, msg, stage, resData): Promise<Response> {
		var data = {
			status: false,
			stage: stage || 1,
			code: responseCode[code].code,
			message: msg ? msg : responseCode[code].msg,
			data: resData
		};
		return res.status(500).json(data);
	};
	
	public notFoundResponse (res, code): Promise<Response> {
		var data = {
			status: false,
			code: responseCode[code].code,
			message: responseCode[code].msg
		};
		return res.status(404).json(data);
	};
	
	public validationErrorWithData (res, code, data): Promise<Response> {
		var resData = {
			status: false,
			code: responseCode[code].code,
			message: responseCode[code].msg,
			data: data
		};
		return res.status(400).json(resData);
	};
	
	public unauthorizedResponse(res, code): Promise<Response> {
		var data = {
			status: false,
			code: responseCode[code].code,
			message: responseCode[code].msg
		};
		return res.status(401).json(data);
	};
}

export default new ApiResponse();
