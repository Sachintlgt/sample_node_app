import * as express from 'express';
import * as logger from 'morgan';
import * as cors from 'cors';
import * as cookieParser from 'cookie-parser';
import * as swaggerJSDoc from 'swagger-jsdoc';
import * as swaggerUi from 'swagger-ui-express';
import Options from './docTemplate/swagger';

import IndexRouter from './routes/index';
import ApiRouter from './routes/api';
import apiResponse from './helpers/apiResponse';
import db from './helpers/databaseConfig';
import cron from './helpers/cron';
import Redis from './helpers/redis';
import { log } from 'util';

class App {

	public app: express.Application;
	private swaggerDocs: any;
	private db: any;
	private indexRoute: IndexRouter = new IndexRouter();
	private apiRouter: ApiRouter = new ApiRouter();
	private redis: Redis = new Redis();


	constructor() {
		this.app = express(); //run the express instance and store in app
		this.db = db;
		this.swaggerDocs = swaggerJSDoc(Options);	
		this.config();
		cron.dailyReportCron();
		cron.dailyFormulationReports();
		cron.weeklyEnergyDrinkReport();
	}

	private config(): void | any{
		this.db
        .authenticate()
        .then(function (err: any) {
			if (err) throw err;
			if (process.env.NODE_ENV !== "test") {
				console.log("Connected to db");
				console.log("App is running ... \n");
				console.log("Press CTRL + C to stop the process. \n");
			}
		})
        .catch( function (err: any) {
			console.log('db error', err);
			if (err.code === 'PROTOCOL_CONNECTION_LOST') { // Connection to the MySQL server is usually
				this.db.handleDisconnect();                         // lost due to either server restart, or a
			} else {                                      // connnection idle timeout (the wait_timeout
				throw err;                                  // server variable configures this)
			}
		});


		if (process.env.NODE_ENV !== "test") {
			this.app.use(logger("dev"));
		}

		this.app.use(`/api/${process.env.APP_VERSION}/api-docs`, swaggerUi.serve, swaggerUi.setup(this.swaggerDocs));

		this.app.use(express.json());
		this.app.use(express.urlencoded({ extended: false }));
		this.app.use(cookieParser());

		let setOfOriginAllow = process.env.ALLOW_ORIGINS.split(",");
		
		//To allow cross-origin requests
		const corsOpts = {
			origin: setOfOriginAllow,
			methods: ["GET", "POST","PUT","DELETE","OPTIONS"],
			allowedHeaders: ["Content-Type"],
			credentials: true,
		};
			
		this.app.use(cors(corsOpts));
		
		//Route Prefixes
		this.app.use("/", this.indexRoute.route());

		this.app.use(`/api/${process.env.APP_VERSION}/`, this.apiRouter.route());

		// throw 404 if URL not found
		this.app.use("*", function (req: express.Request, res: express.Response) {
			return apiResponse.notFoundResponse(res, 'GEN0001');
		});

		this.app.use((err: any, req: express.Request, res: express.Response) => {
			if (err.name == "UnauthorizedError") {
				return apiResponse.unauthorizedResponse(res, 'GEN0002');
			}
		});
	}

}

export default new App().app;