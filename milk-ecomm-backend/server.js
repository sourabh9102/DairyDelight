const dotenv = require('dotenv');
dotenv.config({ path: './config.env' });
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes');
const path = require('path');
const multer = require('multer');


const app = express();
const port = process.env.PORT || 5001;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(bodyParser.json());
app.use(cors(
  {
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials: true
  }
));
app.use('/auth', authRoutes);


app.get('/', (req, res) => {
  if (req.session.fname) {
    return res.json({ valid: true, fname: req.session.fname })
  } else {
    return res.json({ valid: false })
  }
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

