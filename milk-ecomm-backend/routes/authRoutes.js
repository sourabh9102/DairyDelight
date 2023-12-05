const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('../db');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
dotenv.config({ path: './config.env' });



router.post('/register', (req, res) => {
    const sql = "INSERT INTO users (`fname`, `lname`, `uname`, `email`, `password`, `phone`, `address`, `state`, `city`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const saltRounds = 10;

    bcrypt.genSalt(saltRounds, function (err, salt) {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
            if (err) {
                console.log(err);
            }
            else {
                const values = [
                    req.body.fname,
                    req.body.lname,
                    req.body.uname,
                    req.body.email,
                    hash,
                    req.body.phone,
                    req.body.address,
                    req.body.state,
                    req.body.city
                ];
                const checkEmailSql = "SELECT * FROM users WHERE `email` = ? OR `phone` = ?";
                db.query(checkEmailSql, [req.body.email, req.body.phone], (err, result) => {
                    if (err) {
                        console.error('Error fetching user data from the database:', err);
                        res.status(500).json({ success: false, message: 'Error fetching user data from the database.' });
                    } else {
                        if (result.length > 0) {
                            res.status(400).json({ success: false, message: 'Email/Phone number already registered.' });
                        }
                        else {
                            db.query(sql, values, (err, data) => {
                                if (err) {
                                    console.error('Error inserting user data:', err);
                                    res.status(500).json({ success: false, message: 'Error inserting user data.' });
                                } else {
                                    res.status(200).json({ success: true, message: 'User registered successfully.', data });
                                }
                            });
                        }
                    }
                });
            }
        });
    })
});



// app.use((req, res, next) => {
//     getUserData()
//         .then((userData) => {
//             req.userData = userData;
//             next();
//         })
//         .catch((err) => {
//             console.error('Error retrieving user data:', err);
//             req.userData = null;
//             next();
//         });
// });




router.post('/login', (req, res) => {
    try {
        const sql = "SELECT * FROM users WHERE `email` = ? ";
        db.query(sql, [req.body.email], (err, data) => {
            console.log('User data fetched from database:', data);
            if (err) {
                console.error('Error fetching user data from the database:', err);
                return res.status(500).json({ success: false, message: 'Error fetching user data from the database.' });
            }

            if (data.length === 0) {
                return res.status(401).json({ success: false, message: 'Invalid email or password.' });
            }

            const user = data[0];
            try {
                bcrypt.compare(req.body.password, user.password, (bcryptErr, bcryptRes) => {
                    if (bcryptErr) {
                        console.log("An error occurred during password comparison:", bcryptErr);
                        return res.status(500).json({ success: false, message: 'Error comparing passwords.' });
                    }
                    if (bcryptRes) {
                        req.session.fname = user.fname;
                        const name = user.name;
                        const token = jwt.sign({ name }, process.env.JWT_SECRET_KEY, { expiresIn: 300 });
                        console.log(token, 'token');
                        res.cookie('token', token);

                        const email = req.body.email;
                        const savedToken = {};

                        const userData = {
                            firstName: user.fname,
                            lastName: user.lname,
                            address: user.address,
                        }

                        console.log(userData, "user ke bare me");




                        const updateTokenSql = "UPDATE users SET token = ? where email = ?";
                        db.query(updateTokenSql, [token, email], (updateErr, updateResult) => {
                            if (updateErr) {
                                console.error('Error updating token in the database:', updateErr);
                                return res.status(500).send("Couldn't update token in the database.");
                            } else {
                                savedToken[email] = token;
                                // return res.status(200).send("Sent OTP email.");
                            }
                        });
                        return res.json({ Login: true, token, data: user, userData });
                    } else {
                        return res.status(401).json({ Login: false });
                    }
                });
            } catch (bcryptErr) {
                console.log("An error occurred:", err);
                return res.status(500).json({ success: false, message: 'An error occurred.' });
            }
        });

        try {
            const savedOTPS = {};
            const transporter = nodemailer.createTransport({
                host: "smtp.gmail.com",
                port: 587,
                secure: false,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            let email = req.body.email;
            let digits = '0123456789';
            let limit = 4;
            let otp = '';

            for (i = 0; i < limit; i++) {
                otp += digits[Math.floor(Math.random() * 10)];
            }

            const options = {
                from: 'tech.bht@gmail.com',
                to: email,
                subject: "Email account verify",
                html: `<p>Enter the OTP: ${otp} to verify your email account</p>`,
            };

            transporter.sendMail(options, function (error, info) {
                if (error) {
                    console.log(error);
                    // return res.status(500).send("Couldn't send OTP email.");
                } else {
                    const updateOtpSql = "UPDATE users SET otp = ? where email = ?";
                    db.query(updateOtpSql, [otp, email], (updateErr, updateResult) => {
                        if (updateErr) {
                            console.error('Error updating OTP in the database:', updateErr);
                            return res.status(500).send("Couldn't update OTP in the database.");
                        } else {
                            savedOTPS[email] = otp;
                            console.log(savedOTPS[email], " otp isko bahar lana h");
                            setTimeout(() => {
                                delete savedOTPS[email];
                            }, 6000);
                            // return res.json({ Status: "Success", otp: savedOTPS[email] });
                        }
                    });
                }
            });
        } catch (otpError) {
            console.log("An OTP error occurred:", otpError);
            return res.status(500).json({ success: false, message: 'An OTP error occurred.' });
        }
    } catch (error) {
        console.log("An error occurred:", error);
        return res.status(500).json({ success: false, message: 'An error occurred.' });
    }
});

router.post('/subscribe', (req, res) => {
    const subscribeSql = "INSERT INTO subscription (`subscribeEmail`) VALUES (?)";
    const email = req.body.subscribeEmail;
    db.query(subscribeSql, [email], (err, data) => {
        if (err) {
            console.error('Error inserting email into the database:', err);
            return res.status(500).json({ success: false, message: 'Error inserting email into the database.' });
        } else {
            return res.status(200).json({ success: true });
        }
    })
});

router.post('/verify', (req, res) => {
    const enteredOtp = req.body.otp;
    const token = req.cookies.token;
    const verifySql = "SELECT otp FROM users WHERE `token` = ?";
    db.query(verifySql, token, (err, data) => {
        if (err) {
            console.error('Error fetching OTP from the database:', err);
            return res.status(500).json({ success: false, message: 'Error fetching OTP from the database.' });
        }
        const storedOtp = (data && data.length > 0) ? data[0].otp : undefined;
        if (storedOtp !== undefined) {
            if (storedOtp == enteredOtp) {
                return res.status(200).json({ success: true });
            } else {
                return res.status(401).json({ success: false, message: 'Invalid OTP.' });
            }
        } else {
            console.log("No OTP found.")
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});


router.post('/verifyEmail', (req, res) => {
    const enteredEmail = req.body.email;
    const sql = "SELECT * FROM users WHERE `email` = ?";
    db.query(sql, [enteredEmail], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Internal server error" });
        } else if (results.length > 0) {
            try {
                const email = results[0].email;
                res.setHeader('Content-Type', 'application/json');
                const savedOTPS = {};
                const transporter = nodemailer.createTransport({
                    host: "smtp.gmail.com",
                    port: 587,
                    secure: false,
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_PASS,
                    },
                });

                let digits = '0123456789';
                let limit = 4;
                let otp = '';

                for (let i = 0; i < limit; i++) {
                    otp += digits[Math.floor(Math.random() * 10)];
                }

                const options = {
                    from: 'tech.bht@gmail.com',
                    to: email,
                    subject: "Testing node emails",
                    html: `<p>Enter the OTP: ${otp} to verify your email account</p>`,
                };

                transporter.sendMail(options, function (error, info) {
                    if (error) {
                        console.log(error);
                        // return res.status(500).send("Couldn't send OTP email.");
                    } else {
                        const updateOtpSql = "UPDATE users SET otp = ? where email = ?";
                        db.query(updateOtpSql, [otp, email], (updateErr, updateResult) => {
                            if (updateErr) {
                                console.error('Error updating OTP in the database:', updateErr);
                                return res.status(500).send("Couldn't update OTP in the database.");
                            } else {
                                savedOTPS[email] = otp;
                                console.log(savedOTPS[email], " otp isko bahar lana h");
                                setTimeout(() => {
                                    delete savedOTPS[email];
                                }, 60000);
                                // return res.json({ Status: "Success", otp: savedOTPS[email] });
                            }
                        });
                    }
                });

                const token = jwt.sign({ email }, process.env.JWT_SECRET_KEY, { expiresIn: '1d' });
                res.cookie('token', token);

                const savedToken = {};
                const updateTokenSql = "UPDATE users SET token = ? where email = ?";
                db.query(updateTokenSql, [token, email], (updateErr, updateResult) => {
                    if (updateErr) {
                        console.error('Error updating token in the database:', updateErr);
                        return res.status(500).send("Couldn't update token in the database.");
                    } else {
                        savedToken[email] = token;
                        console.log(savedToken[email], "Generated OTP");
                        // return res.status(200).send("Sent OTP email.");
                    }
                });
                return res.status(200).json({ success: true, token: token });
            } catch (error) {
                console.log("Error to generate token.", error);
            }
            return res.json({ success: true });
        } else {
            console.log("Email not found");
            return res.status(400).json({ error: "Email not found" });
        }
    })
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname))
    }
})

const upload = multer({
    storage: storage
})

router.post('/upload', upload.single('file'), (req, res) => {
    const email = req.body.email;
    console.log(req.body.email, "req.body.email");
    const checkTokenSql = "SELECT * FROM users WHERE `email` = ?";
    db.query(checkTokenSql, email, (err, data) => {
        if (err) {
            console.error('Error fetching user token from the database:', err);
            return res.status(500).json({ success: false, message: 'Error fetching user token from the database.' });
        }

        if (data.length === 0) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const { filename } = req.file;
        const updateSql = "UPDATE users SET `photo` = ? WHERE `email` = ?";
        db.query(updateSql, [filename, email], (err, result) => {
            if (err) {
                console.error('Error updating user photo:', err);
                return res.status(500).json({ success: false, message: 'Error updating user photo.' });
            }
            console.log('User photo updated in the database');
            // res.sendFile(path.join(__dirname, '/public/images', filename));
            res.json({ success: true, message: 'File uploaded and saved to the database', filename: filename });
        });
    });
});


router.post('/forgotPass', (req, res) => {
    const newPwd1 = req.body.password1;
    const newPwd2 = req.body.password2;
    const token = req.cookies.token;
    const pwdSql = "SELECT * FROM users WHERE `token` = ? ";
    db.query(pwdSql, token, (err, data) => {
        if (err) {
            console.log("Error fetching token from database.", err);
            return res.status(500).json({ success: false, message: 'Error fetching OTP from the database.' });
        } else if (newPwd1 === newPwd2) {
            const sql = "UPDATE users SET password = ? WHERE token = ?";
            const saltRounds = 10;
            bcrypt.genSalt(saltRounds, function (err, salt) {
                bcrypt.hash(newPwd1, salt, (err, hash) => {
                    if (err) {
                        console.log(err);
                    } else {
                        db.query(sql, [hash, token], (error, result) => {
                            if (error) {
                                console.log("Error updating password in the database", error);
                                return res.status(500).json({ success: false, message: 'Error updating password in the database.' });
                            } else {
                                return res.status(200).json({ success: true, message: 'Password updated successfully.' });
                            }
                        });
                    }
                });
            })
            // return res.status(200).json({ success: true, message: 'Password matched successfully.' });
        } else {
            console.log("Password do not match");
            return res.status(401).json({ success: false, message: 'Password did not matched.' });
        }
    });

});

router.post('/changePass', (req, res) => {
    const newPwd1 = req.body.password1;
    const newPwd2 = req.body.password2;
    const token = req.cookies.token;
    const pwdSql = "SELECT * FROM users WHERE `token` = ? ";
    db.query(pwdSql, token, (err, data) => {
        if (err) {
            console.log("Error fetching token from database.", err);
            return res.status(500).json({ success: false, message: 'Error fetching OTP from the database.' });
        } else if (newPwd1 === newPwd2) {
            const sql = "UPDATE users SET password = ? WHERE token = ?";
            const saltRounds = 10;
            bcrypt.genSalt(saltRounds, function (err, salt) {
                bcrypt.hash(newPwd1, salt, (err, hash) => {
                    if (err) {
                        console.log(err);
                    } else {
                        db.query(sql, [hash, token], (error, result) => {
                            if (error) {
                                console.log("Error updating password in the database", error);
                                return res.status(500).json({ success: false, message: 'Error updating password in the database.' });
                            } else {
                                return res.status(200).json({ success: true, message: 'Password updated successfully.' });
                            }
                        });
                    }
                });
            })
            // return res.status(200).json({ success: true, message: 'Password matched successfully.' });
        } else {
            console.log("Password do not match");
            return res.status(401).json({ success: false, message: 'Password did not matched.' });
        }
    });

});


router.get('/logout', (req, res) => {
    try {
        req.session.destroy();
        res.clearCookie('token');
        return res.json({ Status: "Success" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ Status: "Error" });
    }
});




// const verifyUser = (req, res, next) => {
//     const token = req.cookies.token;
//     if (!token) {
//         return res.json({ Message: "There is no token" })
//     } else {
//         jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
//             if (err) {
//                 return res.json({ Message: "Authentication Error." })
//             } else {
//                 req.name = decoded.name;
//                 next();
//             }
//         })
//     }
// }

// router.get('/', verifyUser, (req, res) => {
//     return res.json({ Status: "Success", name: req.name })
// })


module.exports = router;