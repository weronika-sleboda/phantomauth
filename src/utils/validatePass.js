
export const validatePass = (password) => {
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{8,}$/;
  const invalidPass = !passRegex.test(password);
  if(invalidPass) {
    const error = new Error('Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.');
    error.status = 400;
    throw error;
  }
}