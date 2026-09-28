function sanitizeProfileUpdate({ name, username, email, age }) {
  const cleanedName = String(name || '').trim();
  const cleanedUsername = String(username || '').trim().toLowerCase();
  const cleanedEmail = String(email || '').trim().toLowerCase();
  const cleanedAge = Number(age);

  if (!cleanedName) {
    throw new Error('Name is required.');
  }

  if (!cleanedUsername) {
    throw new Error('Username is required.');
  }

  if (!cleanedEmail) {
    throw new Error('Email is required.');
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(cleanedEmail)) {
    throw new Error('Please enter a valid email address.');
  }

  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  if (!usernameRegex.test(cleanedUsername)) {
    throw new Error('Username must be 3-30 characters using letters, numbers, or underscores.');
  }

  if (Number.isNaN(cleanedAge) || cleanedAge < 13 || cleanedAge > 120) {
    throw new Error('Age must be between 13 and 120.');
  }

  return {
    name: cleanedName,
    username: cleanedUsername,
    email: cleanedEmail,
    age: cleanedAge
  };
}

module.exports = { sanitizeProfileUpdate };
