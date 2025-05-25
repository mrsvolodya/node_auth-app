import bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import { ApiError } from '../exceptions/api.error.js';
import { ResetToken } from '../models/resetToken.js';
import { User } from '../models/user.js';
import { emailService } from '../services/email.service.js';
import { jwtService } from '../services/jwt.service.js';
import { tokenService } from '../services/token.service.js';
import { userService } from '../services/user.service.js';
import { generateTokens } from '../utils/generateTokens.js';

const EMAIL_PATTERN = /^[\w.+-]+@([\w-]+\.){1,3}[\w-]{2,}$/;

function validateEmail(value) {
  if (!value) {
    return 'Email is required';
  }

  if (!EMAIL_PATTERN.test(value)) {
    return 'Email is not valid';
  }
}

function validatePassword(value) {
  if (!value) {
    return 'Password is required';
  }

  if (value.length < 6) {
    return 'At least 6 characters';
  }
}

const registration = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  const errors = {
    email: validateEmail(email),
    password: validatePassword(password),
  };

  if (errors.email || errors.password) {
    throw ApiError.badRequest('Bad request', 400, errors);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await userService.registration(firstName, lastName, email, hashedPassword);

  res.send({ message: 'Activation email was sent!' });
};

const activate = async (req, res) => {
  const { activationToken } = req.params;

  const user = await User.findOne({ where: { activationToken } });

  if (!user) {
    return res.sendStatus(404);
  }

  user.activationToken = null;
  await user.save();

  await generateTokens(res, user);
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await userService.findByEmail(email);

  if (!user) {
    throw ApiError.badRequest('No such user');
  }

  if (user.activationToken) {
    throw ApiError.badRequest('Please activate your account first');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw ApiError.badRequest('Wrong password');
  }

  await generateTokens(res, user);
};

const logout = async (req, res) => {
  const { refreshToken } = req.cookies;
  const userData = jwtService.verify(refreshToken);

  if (!userData || !refreshToken) {
    throw ApiError.unauthorized();
  }

  await tokenService.remove(userData.id);

  res.clearCookie('refreshToken');

  res.sendStatus(204);
};

const refresh = async (req, res) => {
  const { refreshToken } = req.cookies;
  const userData = await jwtService.verifyRefresh(refreshToken);

  const token = await tokenService.getByToken(refreshToken);

  if (!userData || !token) {
    throw ApiError.unauthorized();
  }

  const user = await userService.findByEmail(userData.email);

  if (!user) {
    throw ApiError.unauthorized();
  }

  generateTokens(res, user);
};

const requestReset = async (req, res) => {
  const { email } = req.body;

  // Validate email
  const emailError = validateEmail(email);

  if (emailError) {
    throw ApiError.badRequest(emailError);
  }

  // Find user by email
  const user = await userService.findByEmail(email);

  // Don't reveal if user exists or not for security reasons
  if (!user) {
    return res.send({
      message: 'Password reset link sent if account exists',
    });
  }

  // Generate a reset token using Node.js built-in crypto
  const resetToken = Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        crypto.getRandomValues(new Uint8Array(32)),
      ),
    ),
  )
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  // 1 hour from now
  const expiresAt = new Date(Date.now() + 3600000);

  // Remove any existing reset tokens for this user
  await ResetToken.destroy({ where: { userId: user.id } });

  // Create new reset token
  await ResetToken.create({
    resetToken: resetToken,
    expiresAt,
    userId: user.id,
  });

  // Send the reset email
  await emailService.sendEmailChangeConfirmation(user.email, resetToken);

  // Return success message
  return res.send({
    message: 'Password reset link sent if account exists',
  });
};

const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  // Validate password
  const passwordError = validatePassword(password);

  if (passwordError) {
    throw ApiError.badRequest(passwordError);
  }

  // Find user by reset token and check if token is expired
  const resetTokenRecord = await ResetToken.findOne({
    where: {
      resetToken,
      expiresAt: {
        [Op.gt]: new Date(),
      },
      used: false,
    },
    include: { model: User, required: true },
  });

  if (!resetTokenRecord || resetTokenRecord.used) {
    throw ApiError.badRequest('Invalid or expired reset token');
  }

  const user = resetTokenRecord.user;

  // Hash the new password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Update user's password and clear reset token fields
  user.password = hashedPassword;
  resetTokenRecord.resetToken = null;
  resetTokenRecord.resetTokenExpiry = null;
  resetTokenRecord.used = true;
  await resetTokenRecord.save();
  await user.save();

  return res.send({ message: 'Password has been reset successfully' });
};

export const authController = {
  registration,
  activate,
  login,
  logout,
  refresh,
  requestReset,
  resetPassword,
};
