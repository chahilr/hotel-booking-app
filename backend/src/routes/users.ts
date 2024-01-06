import express, { Request, Response } from 'express';
import User from '../models/user';
import jwt from 'jsonwebtoken';
import { check, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';

const router = express.Router();

router.post(
  '/register',
  [
    check('firstName', 'First Name is required').isString(),
    check('lastName', 'Last Name is required').isString(),
    check('email', 'Email is required').isEmail(),
    check('password', 'Password with 6 or more characters required').isLength({
      min: 6,
    }),
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array() });
    }
    try {
      let user = await User.findOne({
        email: req.body.email,
      });
      if (user) {
        return res.status(400).json({ message: 'User already exists' });
      }
      user = new User(req.body);
      await user.save();
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET_KEY as string,
        {
          expiresIn: '1d',
        }
      );
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 86400000,
      });
      return res.status(200).send({ message: 'User registered OK' });
    } catch (err) {
      console.log(err);

      res.status(500).send({ message: 'Something went wrong' });
    }
  }
);

router.get(
  '/login',
  [
    check('email', 'Email is required').isEmail(),
    check('password', 'Password is required').isLength({ min: 6 }),
  ],
  async (req: Request, res: Response) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res
        .status(400)
        .json({ message: 'Email or password is incorrect.' });
    }
    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (validPassword) {
      return res.status(200).send();
    } else {
      return res.status(404).send();
    }
    // console.log(req.headers['auth-token'])
    // jwt.verify(req.headers['auth-token'] as string, process.env.JWT_SECRET_KEY as string, (err) => {
    //   if (err) {
    //     res.status(404).send();
    //   } else {
    //     res.status(200).send();
    //   }
    // });
  }
);

export default router;
