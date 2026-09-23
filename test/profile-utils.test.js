const test = require('node:test');
const assert = require('node:assert/strict');

const { sanitizeProfileUpdate } = require('../utils/profile');

test('sanitizeProfileUpdate normalizes valid profile data', () => {
  const result = sanitizeProfileUpdate({
    name: '  Alice  ',
    username: '  alice_user  ',
    email: 'ALICE@example.com',
    age: '29'
  });

  assert.deepStrictEqual(result, {
    name: 'Alice',
    username: 'alice_user',
    email: 'alice@example.com',
    age: 29
  });
});

test('sanitizeProfileUpdate rejects invalid username values', () => {
  assert.throws(() => {
    sanitizeProfileUpdate({ name: 'Alice', username: 'bad user', email: 'alice@example.com', age: 30 });
  }, /Username/);
});
