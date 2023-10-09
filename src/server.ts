import * as dotenv from 'dotenv';
dotenv.config();
import * as debug from 'debug';
import * as http from 'http';
import * as path from 'path';
import {Server} from 'socket.io';
global.path = path.dirname(require.main.filename);

import app from './app';
import Chat from './routes/chat';

/**
 * Get port from environment and store in Express.
 */

var port = normalizePort(process.env.APP_PORT || '3000');
var domain = process.env.APP_URL || '127.0.0.1';
app.set('domain', domain);
app.set('port', port);

/**
 * Create HTTP server.
 */

var server = http.createServer(app);
var io = new Server(server);

new Chat().connection(io);


/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

/**
 * Normalize a port into a number, string, or false.
 */

function normalizePort(val : string) : any {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error: any) : void | any {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() : void {
  var addr = server.address();
  var bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;
  debug('Listening on ' + bind);
}
