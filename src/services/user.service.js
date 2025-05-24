import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../exceptions/api.error.js';
import { User } from '../models/user.js';
import normalizeUser from '../utils/normalizeUser.js';
import { emailService } from './email.service.js';

async function findByEmail(email) {
  return User.findOne({ where: { email } });
}

async function getExistingUserById(id) {
  const user = await User.findByPk(id);

  if (!user) {
    throw ApiError.badRequest('User not found');
  }

  return user;
}

async function registration(firstName, lastName, email, password) {
  const activationToken = uuidv4();

  const isExistUser = await findByEmail(email);

  if (isExistUser) {
    throw ApiError.badRequest('User already exists!');
  }

  await User.create({
    firstName,
    lastName,
    email,
    password,
    activationToken,
  });
  await emailService.sendActivationEmail(email, activationToken);
}

async function updateFullName(id, firstName, lastName) {
  const user = await getExistingUserById(id);

  await user.update({ firstName, lastName });

  return normalizeUser(user);
}

async function updatePassword(id, password) {
  const user = await getExistingUserById(id);

  await user.update({ password });

  return true;
}

async function updateEmail(id, email) {
  const user = await getExistingUserById(id);

  await user.update({ email });

  return normalizeUser(user);
}

export const userService = {
  registration,
  findByEmail,
  updateFullName,
  updatePassword,
  updateEmail,
  getExistingUserById,
};
