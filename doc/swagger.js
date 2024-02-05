const swaggerAutogen = require('swagger-autogen')();

const doc = {
  info: {
    title: 'Movies API',
    description: 'Description'
  },
  host: 'localhost:8080'
};

const outputFile = './swagger-output.json';
const routes =  ['.././api/index.js'];

/* NOTE: If you are using the express Router, you must pass in the 'routes' only the 
root file where the route starts, such as index.js, app.js, routes.js, etc ... */

swaggerAutogen(outputFile, routes, doc);

// const Run = () => {
//     swaggerAutogen(outputFile, routes, doc);
// }

// module.exports = { Run };