import validator from 'validator';

export const validateEmail = (email) => {
  const invalidEmail = !validator.isEmail(email);
  if(invalidEmail) {
    const error = new Error('Invalid email');
    error.status = 400;
    throw error;
  }
}
