import { useState } from 'react';
import axios from 'axios';

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await axios.post('/api/login', {
        username: username.trim(),
        password,
      });
      setUsername('');
      setPassword('');
      onSuccess?.(data.user);
    } catch (err) {
      console.error('Login failed', err);
      setError(err.response?.data?.message || 'Login failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>Grant Mesra Portal</h1>
        <p className="login-subtitle">Sign in with your operator account to continue.</p>

        {error && <div className="alert alert-error">{error}</div>}

        <label>
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
        </label>

        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        <button type="submit" className="btn primary" disabled={loading}>
          {loading ? 'Signing in…' : 'Sign In'}
        </button>

        <p className="login-hint">Contact an administrator if you need access.</p>
      </form>
    </div>
  );
}
