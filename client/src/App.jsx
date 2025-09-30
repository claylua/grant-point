import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import Login from './components/Login.jsx';

const apiBase = import.meta.env.VITE_API_BASE_URL || '';
if (apiBase) {
  axios.defaults.baseURL = apiBase.replace(/\/$/, '');
}
axios.defaults.withCredentials = true;

const initialCounts = {
  total: 0,
  pending: 0,
  success: 0,
  error: 0,
  in_progress: 0,
  processed: 0,
  remaining: 0,
};

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function formatDate(value) {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}

function formatDetails(details) {
  if (details === null || details === undefined) {
    return '—';
  }
  if (typeof details === 'string') {
    return details;
  }
  try {
    return JSON.stringify(details, null, 2);
  } catch (err) {
    return String(details);
  }
}

export default function App() {
  const [authChecked, setAuthChecked] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);

  const [status, setStatus] = useState(null);
  const [environments, setEnvironments] = useState([]);
  const [selectedEnv, setSelectedEnv] = useState('staging');
  const [uploading, setUploading] = useState(false);
  const [processingMessage, setProcessingMessage] = useState('');
  const [errors, setErrors] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [selectedFileName, setSelectedFileName] = useState('');

  const [users, setUsers] = useState([]);
  const [userForm, setUserForm] = useState({ username: '', password: '', role: 'user' });
  const [userLoading, setUserLoading] = useState(false);
  const [userMessage, setUserMessage] = useState('');
  const [userError, setUserError] = useState('');

  const [auditLogs, setAuditLogs] = useState([]);
  const [auditError, setAuditError] = useState('');

  const fileInputRef = useRef(null);

  const pollInterval = status?.pollIntervalMs || 3000;
  const processingState = status?.processing || {};
  const counts = status?.counts || initialCounts;
  const batch = status?.batch || null;
  const isAdmin = currentUser?.role === 'admin';
  const canViewAudit = currentUser?.username?.toLowerCase() === 'clay';

  const clearDataState = useCallback(() => {
    setStatus(null);
    setErrors([]);
    setProcessingMessage('');
    setSuccessMessage('');
    setErrorMessage('');
    setSelectedFileName('');
    setUserMessage('');
    setUserError('');
    setUserForm({ username: '', password: '', role: 'user' });
    setAuditLogs([]);
    setAuditError('');
  }, []);

  const fetchCurrentUser = useCallback(async () => {
    try {
      const { data } = await axios.get('/api/me');
      setCurrentUser(data.user);
    } catch (err) {
      setCurrentUser(null);
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    fetchCurrentUser();
  }, [fetchCurrentUser]);

  const fetchStatus = useCallback(async () => {
    if (!currentUser) return;
    try {
      const response = await axios.get('/api/status');
      setStatus(response.data);
    } catch (err) {
      if (err.response?.status === 401) {
        setCurrentUser(null);
        return;
      }
      console.error('Failed to fetch status', err);
      setErrorMessage(err.response?.data?.message || 'Failed to fetch status.');
    }
  }, [currentUser]);

  const fetchEnvironments = useCallback(async () => {
    if (!currentUser) return;
    try {
      const response = await axios.get('/api/environments');
      setEnvironments(response.data.environments);
      if (!selectedEnv && response.data.environments.length) {
        setSelectedEnv(response.data.environments[0].key);
      }
    } catch (err) {
      if (err.response?.status === 401) {
        setCurrentUser(null);
        return;
      }
      console.error('Failed to fetch environments', err);
      setErrorMessage(err.response?.data?.message || 'Failed to fetch environments.');
    }
  }, [currentUser, selectedEnv]);

  const fetchErrors = useCallback(async () => {
    if (!currentUser) return;
    try {
      const response = await axios.get('/api/errors?limit=200');
      setErrors(response.data.errors || []);
    } catch (err) {
      if (err.response?.status === 401) {
        setCurrentUser(null);
      }
      console.error('Failed to fetch errors', err);
    }
  }, [currentUser]);

  const fetchAuditLogs = useCallback(async () => {
    if (!canViewAudit) {
      setAuditLogs([]);
      setAuditError('');
      return;
    }
    try {
      const response = await axios.get('/api/audit-logs?limit=200');
      setAuditLogs(response.data.logs || []);
      setAuditError('');
    } catch (err) {
      if (err.response?.status === 401) {
        setCurrentUser(null);
        return;
      }
      console.error('Failed to fetch audit logs', err);
      setAuditError(err.response?.data?.message || 'Failed to fetch audit logs.');
    }
  }, [canViewAudit]);

  const fetchUsers = useCallback(async () => {
    if (!isAdmin) {
      setUsers([]);
      return;
    }
    try {
      const { data } = await axios.get('/api/users');
      setUsers(data.users || []);
    } catch (err) {
      if (err.response?.status === 401) {
        setCurrentUser(null);
        return;
      }
      console.error('Failed to load users', err);
      setUserError(err.response?.data?.message || 'Failed to load users.');
    }
  }, [isAdmin]);

  useEffect(() => {
    if (!currentUser) {
      clearDataState();
      setEnvironments([]);
      setUsers([]);
      return;
    }

    fetchEnvironments();
    fetchStatus();
    fetchErrors();
    if (isAdmin) {
      fetchUsers();
    }
    if (canViewAudit) {
      fetchAuditLogs();
    } else {
      setAuditLogs([]);
      setAuditError('');
    }
  }, [
    currentUser,
    isAdmin,
    canViewAudit,
    fetchEnvironments,
    fetchStatus,
    fetchErrors,
    fetchUsers,
    fetchAuditLogs,
    clearDataState,
  ]);

  useEffect(() => {
    if (!currentUser) return () => {};
    const interval = setInterval(() => {
      fetchStatus();
      fetchErrors();
      if (isAdmin) {
        fetchUsers();
      }
      if (canViewAudit) {
        fetchAuditLogs();
      }
    }, pollInterval);
    return () => clearInterval(interval);
  }, [currentUser, fetchStatus, fetchErrors, fetchUsers, fetchAuditLogs, pollInterval, isAdmin, canViewAudit]);

  const handleFileSelect = (event) => {
    const file = event.target.files?.[0];
    setSelectedFileName(file ? file.name : '');
  };

  const handleUpload = async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    const file = formData.get('csv');
    if (!file || !file.size) {
      setErrorMessage('Please select a CSV file to upload.');
      return;
    }

    setUploading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const response = await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setSuccessMessage(response.data.message);
      fetchStatus();
    } catch (err) {
      console.error('Upload failed', err);
      setErrorMessage(err.response?.data?.message || 'Failed to upload CSV.');
    } finally {
      setUploading(false);
      event.target.reset();
      setSelectedFileName('');
    }
  };

  const handleReset = async () => {
    if (!isAdmin) {
      return;
    }
    if (!window.confirm('Are you sure you want to delete all data? This will also remove log files.')) {
      return;
    }
    setErrorMessage('');
    setSuccessMessage('');
    try {
      const response = await axios.delete('/api/data?confirm=true');
      setSuccessMessage(response.data.message);
      setErrors([]);
      fetchStatus();
      if (isAdmin) {
        fetchUsers();
      }
    } catch (err) {
      console.error('Failed to delete data', err);
      setErrorMessage(err.response?.data?.message || 'Failed to delete data.');
    }
  };

  const handleProcess = async () => {
    if (!selectedEnv) {
      setErrorMessage('Choose an environment before starting.');
      return;
    }

    let confirmProduction = false;
    if (selectedEnv === 'production') {
      confirmProduction = window.confirm('You are about to run against PRODUCTION. Are you sure you want to continue?');
      if (!confirmProduction) {
        return;
      }
    }

    setProcessingMessage('');
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const response = await axios.post('/api/process', {
        environment: selectedEnv,
        confirmProduction,
      });
      setProcessingMessage(response.data.message);
      fetchStatus();
    } catch (err) {
      console.error('Failed to start processing', err);
      setErrorMessage(err.response?.data?.message || 'Failed to start processing.');
    }
  };

  const handleDownloadLog = () => {
    window.open('/api/log-file', '_blank');
  };

  const progressPercent = useMemo(() => {
    if (!counts.total) return 0;
    return Math.round(((counts.success + counts.error) / counts.total) * 100);
  }, [counts]);

  const handleLogout = async () => {
    try {
      await axios.post('/api/logout');
    } catch (err) {
      console.error('Failed to logout', err);
    }
    setCurrentUser(null);
    setAuthChecked(true);
    clearDataState();
    setEnvironments([]);
    setUsers([]);
    setSelectedEnv('staging');
  };

  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setAuthChecked(true);
    clearDataState();
  };

  const handleUserFormChange = (event) => {
    const { name, value } = event.target;
    setUserForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleCreateUser = async (event) => {
    event.preventDefault();
    setUserLoading(true);
    setUserError('');
    setUserMessage('');
    try {
      await axios.post('/api/users', {
        username: userForm.username.trim(),
        password: userForm.password,
        role: userForm.role,
      });
      setUserForm({ username: '', password: '', role: 'user' });
      setUserMessage('User created successfully.');
      fetchUsers();
    } catch (err) {
      console.error('Failed to create user', err);
      setUserError(err.response?.data?.message || 'Failed to create user.');
    } finally {
      setUserLoading(false);
    }
  };

  const handleChangeUserRole = async (id, role) => {
    if (!window.confirm('Update user role?')) {
      return;
    }
    try {
      await axios.put(`/api/users/${id}`, { role });
      setUserMessage('User role updated.');
      setUserError('');
      fetchUsers();
    } catch (err) {
      console.error('Failed to update user', err);
      setUserError(err.response?.data?.message || 'Failed to update user.');
    }
  };

  const handleResetUserPassword = async (id, username) => {
    const password = window.prompt(`Enter a new password for ${username}`);
    if (!password) {
      return;
    }
    try {
      await axios.put(`/api/users/${id}`, { password });
      setUserMessage('Password updated.');
      setUserError('');
    } catch (err) {
      console.error('Failed to reset password', err);
      setUserError(err.response?.data?.message || 'Failed to reset password.');
    }
  };

  const handleDeleteUser = async (id, username) => {
    if (!window.confirm(`Remove user ${username}?`)) {
      return;
    }
    try {
      await axios.delete(`/api/users/${id}`);
      setUserMessage('User deleted.');
      setUserError('');
      fetchUsers();
    } catch (err) {
      console.error('Failed to delete user', err);
      setUserError(err.response?.data?.message || 'Failed to delete user.');
    }
  };

  if (!authChecked) {
    return (
      <div className="loading-screen">
        <div className="loading-card">Loading…</div>
      </div>
    );
  }

  if (!currentUser) {
    return <Login onSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="container">
      <header className="page-header">
        <div>
          <h1>Grant Mesra Points Processor</h1>
          <p>Upload Mesra grant CSV files, monitor processing, and review errors.</p>
        </div>
        <div className="user-summary">
          <span>
            Signed in as <strong>{currentUser.username}</strong> ({currentUser.role})
          </span>
          <button type="button" className="btn secondary" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>

      <section className="dashboard">
        <div className="metric-card primary">
          <span className="metric-label">Total Uploaded</span>
          <span className="metric-value">{formatNumber(counts.total)}</span>
          <span className="metric-sub">Rows currently stored in DB</span>
        </div>
        <div className="metric-card">
          <span className="metric-label">Processed</span>
          <span className="metric-value">{formatNumber(counts.success + counts.error)}</span>
          <span className="metric-sub">Completed rows (success + error)</span>
        </div>
        <div className="metric-card success">
          <span className="metric-label">Successful</span>
          <span className="metric-value">{formatNumber(counts.success)}</span>
          <span className="metric-sub">Rows granted without issues</span>
        </div>
        <div className="metric-card warning">
          <span className="metric-label">Pending</span>
          <span className="metric-value">{formatNumber(counts.pending)}</span>
          <span className="metric-sub">Yet to be processed</span>
        </div>
        <div className="metric-card danger">
          <span className="metric-label">Errors</span>
          <span className="metric-value">{formatNumber(counts.error)}</span>
          <span className="metric-sub">Rows with failures</span>
        </div>
      </section>

      {errorMessage && <div className="alert alert-error">{errorMessage}</div>}
      {successMessage && <div className="alert alert-success">{successMessage}</div>}
      {processingMessage && <div className="alert alert-info">{processingMessage}</div>}
      {processingState?.error && <div className="alert alert-error">Processor error: {processingState.error}</div>}

      <section className="card control-card">
        <div className="control-grid">
          <div className="control-block">
            <h2>Processing Controls</h2>
            <p className="control-subtitle">Pick the target environment before starting a run.</p>
            <div className="chip-group">
              {environments.map((env) => (
                <label
                  key={env.key}
                  className={`chip ${selectedEnv === env.key ? 'active' : ''}`}
                >
                  <input
                    type="radio"
                    value={env.key}
                    checked={selectedEnv === env.key}
                    onChange={(event) => setSelectedEnv(event.target.value)}
                  />
                  {env.label}
                </label>
              ))}
            </div>
            {selectedEnv === 'production' && (
              <p className="warning inline">⚠️ Production mode will hit live services. Double-check before proceeding.</p>
            )}
          </div>

          <form onSubmit={handleUpload} className="control-block upload-block">
            <h3>Upload CSV</h3>
            <p className="control-subtitle">Choose a Mesra grant CSV and upload it into the database.</p>
            <input
              ref={fileInputRef}
              type="file"
              name="csv"
              accept=".csv"
              disabled={uploading || counts.total > 0}
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
            <div className="upload-row">
              <button
                type="button"
                className="btn outline"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading || counts.total > 0}
              >
                {selectedFileName || 'Select CSV file'}
              </button>
              <button
                type="submit"
                className="btn primary"
                disabled={uploading || counts.total > 0}
              >
                {uploading ? 'Uploading…' : 'Upload'}
              </button>
            </div>
            {counts.total > 0 && (
              <p className="hint">Reset existing data before uploading a new file.</p>
            )}
          </form>

          <div className="control-block actions-block">
            <h3>Actions</h3>
            <p className="control-subtitle">Run processing, review logs, or reset the workspace.</p>
            <div className="action-buttons">
              <button
                type="button"
                className="btn primary"
                onClick={handleProcess}
                disabled={counts.pending === 0}
              >
                {processingState?.running ? 'Processing…' : 'Start / Continue'}
              </button>
              <button
                type="button"
                className="btn secondary"
                onClick={handleDownloadLog}
                disabled={!batch}
              >
                Download Log
              </button>
              {isAdmin && (
                <button
                  type="button"
                  className="btn danger"
                  onClick={handleReset}
                >
                  Delete Current Data
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="card">
        <h2>Current Batch</h2>
        {batch ? (
          <div className="grid">
            <div>
              <span className="label">Source File</span>
              <span>{batch.source_file}</span>
            </div>
            <div>
              <span className="label">Batch ID</span>
              <span>{batch.id}</span>
            </div>
            <div>
              <span className="label">Status</span>
              <span>{batch.status}</span>
            </div>
            <div>
              <span className="label">Environment</span>
              <span>{batch.environment || '—'}</span>
            </div>
            <div>
              <span className="label">Created</span>
              <span>{formatDate(batch.created_at)}</span>
            </div>
            <div>
              <span className="label">Updated</span>
              <span>{formatDate(batch.updated_at)}</span>
            </div>
          </div>
        ) : (
          <p>No batch uploaded yet.</p>
        )}
        <div className="progress">
          <div className="progress-bar" style={{ width: `${progressPercent}%` }} />
        </div>
        <ul className="stats">
          <li>Total: {formatNumber(counts.total)}</li>
          <li>Processed: {formatNumber(counts.success + counts.error)}</li>
          <li>Pending: {formatNumber(counts.pending)}</li>
          <li>Success: {formatNumber(counts.success)}</li>
          <li>Error: {formatNumber(counts.error)}</li>
        </ul>
      </section>

      {isAdmin && (
        <section className="card">
          <h2>User Management</h2>
          <p className="hint">Only administrators can manage accounts. Configure initial credentials before use.</p>
          {userError && <div className="alert alert-error">{userError}</div>}
          {userMessage && <div className="alert alert-success">{userMessage}</div>}
          <form className="user-form" onSubmit={handleCreateUser}>
            <div className="user-form-grid">
              <input
                type="text"
                name="username"
                placeholder="Username"
                value={userForm.username}
                onChange={handleUserFormChange}
                required
              />
              <input
                type="password"
                name="password"
                placeholder="Password"
                value={userForm.password}
                onChange={handleUserFormChange}
                required
              />
              <select name="role" value={userForm.role} onChange={handleUserFormChange}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
              <button type="submit" className="btn primary" disabled={userLoading}>
                {userLoading ? 'Saving…' : 'Create User'}
              </button>
            </div>
          </form>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.username}</td>
                    <td>
                      <select
                        value={user.role}
                        onChange={(event) => handleChangeUserRole(user.id, event.target.value)}
                        disabled={user.username === currentUser.username}
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td>{formatDate(user.created_at)}</td>
                    <td className="table-actions">
                      <button
                        type="button"
                        className="btn secondary"
                        onClick={() => handleResetUserPassword(user.id, user.username)}
                      >
                        Reset Password
                      </button>
                      <button
                        type="button"
                        className="btn danger"
                        onClick={() => handleDeleteUser(user.id, user.username)}
                        disabled={user.username === currentUser.username}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {!users.length && (
                  <tr>
                    <td colSpan={4}>No additional users yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
      </section>
    )}

      {canViewAudit && (
        <section className="card">
          <h2>Audit Trail</h2>
          <p className="control-subtitle">Latest recorded user actions. Only Clay can see this feed.</p>
          {auditError && <div className="alert alert-error">{auditError}</div>}
          {auditLogs.length === 0 ? (
            <p>No audit events yet.</p>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Details</th>
                    <th>IP</th>
                    <th>Route</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => {
                    const detailText = formatDetails(log.details);
                    const route = [log.method, log.path].filter(Boolean).join(' ');
                    return (
                      <tr key={log.id}>
                        <td>{formatDate(log.created_at)}</td>
                        <td>{log.username || '—'}</td>
                        <td>{log.action || '—'}</td>
                        <td>
                          <pre className="audit-details">{detailText}</pre>
                        </td>
                        <td>{log.ip_address || '—'}</td>
                        <td>{route || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section className="card">
        <h2>Error Details</h2>
        {errors.length === 0 ? (
          <p>No errors recorded.</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Reference</th>
                  <th>Card Number</th>
                  <th>Amount</th>
                  <th>Base</th>
                  <th>Bonus</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {errors.map((row) => (
                  <tr key={row.id}>
                    <td>{row.row_number}</td>
                    <td>{row.reference_id || '—'}</td>
                    <td>{row.card_number}</td>
                    <td>{row.amount}</td>
                    <td>{row.base_points}</td>
                    <td>{row.bonus_points}</td>
                    <td>{row.response_status || '—'}</td>
                    <td>{row.error_message || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <footer>
        <small>
          Processing state: {processingState?.running ? 'Running' : 'Idle'}.
          {processingState?.lastProcessedId && ` Last processed ID: ${processingState.lastProcessedId}.`}
        </small>
      </footer>
    </div>
  );
}
