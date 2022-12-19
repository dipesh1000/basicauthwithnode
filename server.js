const dotenv = require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const connectDB = require('./config/db');
const userRoute = require('./routes/userRoute');
const errorHandler = require('./middleware/errorMiddleware');
const cookieParser = require('cookie-parser');
const app = express();

connectDB();

//Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());

//Routes Middleware
app.use('/api/users', userRoute);
//Routes
app.get('/', (req, res) => {
  res.send('API is Running....');
});

//Error Middleware
app.use(errorHandler);

const PORT = process.env.PORT || 2700;

//connect to db and start server
app.listen(
  PORT,
  console.log(`server running in ${process.env.MONGO_URI} mode on port ${PORT}`)
);
