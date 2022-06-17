const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const saltRounds = 10;

router.get('/signup', (req, res, next) => {
    res.render('auth/signup');
})

router.get('/login', (req, res, next) => {
    res.render('auth/login');
})

router.post('/login', async (req, res, next) => {
    const {username, password} = req.body;
    if (!username || !password){
        res.render('auth/login', {error: 'All fields must be filled'})
        return;
    }
    try {
        const user = await User.findOne({username: username})
        if(!user) {
            res.render('auth/login', {error: 'user name does not exist'})
            return;
        } else {
            const passwordMatch = await bcrypt.compare(password, user.hashedPassword)
            if (passwordMatch) {
                req.session.currentUser = user;
                res.render ('auth/profile', user)
            } else {
                res.render('auth/login', {error : 'wrong password or username'})
                return;
            }
        }        
    } catch (error) {
      next(error);        
    }
})

router.post('/signup', async (req, res, next) => {
    const {username, password} = req.body
    if(!username || !password){
        res.render('auth/signup', { error: 'All fields have to be filled'})
        return;
    }

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/
    if (!regex.test(password)) {
        res.render('auth/signup', { error: 'Password must meet criteria'})
        return;
    }
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);
        await User.create({username, hashedPassword});
        res.redirect('/auth/login')
        
    } catch (error) {
        next(error)        
    }
})

router.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
        if(err){
            next(err)
        } else {
            res.redirect("/auth/login")
        }
    })
})

module.exports = router