export const patterns = {
  strongPassword:
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
};

export const messages = {
  passwordComplexity:
    "Password must contain at least one uppercase, one lowercase, one number and one special character",
  confirmPasswordMismatch: "Passwords do not match",
};
