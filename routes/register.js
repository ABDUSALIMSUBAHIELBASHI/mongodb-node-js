// API URL
const API_URL = 'http://localhost:3000';

// Store auth token
let authToken = localStorage.getItem('token') || null;
let currentUser = JSON.parse(localStorage.getItem('user') || 'null');

// Registration handler
async function handleRegister(event) {
    event.preventDefault();
    
    const registerBtn = document.getElementById('register-btn');
    const spinner = document.getElementById('register-spinner');
    const registerText = document.getElementById('register-text');
    
    registerBtn.disabled = true;
    spinner.style.display = 'inline-block';
    registerText.textContent = 'Registering...';
    
    try {
        const formData = new FormData(event.target);
        
        // Format interests
        const interestsInput = formData.get('interests');
        const interests = interestsInput ? interestsInput.split(',').map(i => i.trim()) : [];
        
        // Format address
        const address = {
            street: formData.get('address[street]') || '',
            city: formData.get('address[city]') || '',
            state: formData.get('address[state]') || '',
            zipCode: formData.get('address[zipCode]') || '',
            country: formData.get('address[country]') || ''
        };
        
        const userData = {
            fullName: formData.get('fullName'),
            email: formData.get('email'),
            password: formData.get('password'),
            phone: formData.get('phone') || '',
            age: formData.get('age') ? parseInt(formData.get('age')) : null,
            gender: formData.get('gender'),
            address: address,
            bio: formData.get('bio') || '',
            interests: interests
        };
        
        const response = await fetch(`${API_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Save token and user data
            authToken = result.token;
            currentUser = result.data;
            localStorage.setItem('token', result.token);
            localStorage.setItem('user', JSON.stringify(result.data));
            
            showMessage('success-message', '✅ Registration successful! Welcome ' + result.data.fullName);
            addNotification('success', 'Registration Successful', `Welcome ${result.data.fullName}!`);
            event.target.reset();
            
            // Update UI for logged in user
            updateUserUI();
        } else {
            showMessage('error-message', '❌ ' + result.error);
            addNotification('error', 'Registration Failed', result.error);
        }
    } catch (error) {
        console.error('Registration error:', error);
        showMessage('error-message', '❌ Registration failed. Please try again.');
        addNotification('error', 'Registration Failed', 'Network error');
    }
    
    registerBtn.disabled = false;
    spinner.style.display = 'none';
    registerText.textContent = '📝 Register Account';
}

// Login handler
async function handleLogin(event) {
    event.preventDefault();
    
    const loginBtn = document.getElementById('login-btn');
    const spinner = document.getElementById('login-spinner');
    const loginText = document.getElementById('login-text');
    
    loginBtn.disabled = true;
    spinner.style.display = 'inline-block';
    loginText.textContent = 'Logging in...';
    
    try {
        const formData = new FormData(event.target);
        
        const loginData = {
            email: formData.get('email'),
            password: formData.get('password')
        };
        
        const response = await fetch(`${API_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(loginData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            authToken = result.token;
            currentUser = result.data;
            localStorage.setItem('token', result.token);
            localStorage.setItem('user', JSON.stringify(result.data));
            
            showMessage('success-message', '✅ Login successful! Welcome back ' + result.data.fullName);
            addNotification('success', 'Login Successful', `Welcome back ${result.data.fullName}!`);
            event.target.reset();
            
            // Update UI for logged in user
            updateUserUI();
            
            // Load user messages if logged in
            if (currentUser) {
                loadUserMessages(currentUser._id);
            }
        } else {
            showMessage('error-message', '❌ ' + result.error);
            addNotification('error', 'Login Failed', result.error);
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('error-message', '❌ Login failed. Please try again.');
        addNotification('error', 'Login Failed', 'Network error');
    }
    
    loginBtn.disabled = false;
    spinner.style.display = 'none';
    loginText.textContent = '🔑 Login';
}

// Update UI based on login status
function updateUserUI() {
    const header = document.querySelector('.header');
    let userInfo = document.getElementById('user-info');
    
    if (!userInfo) {
        userInfo = document.createElement('div');
        userInfo.id = 'user-info';
        userInfo.style.marginTop = '20px';
        userInfo.style.padding = '15px';
        userInfo.style.background = 'rgba(255,255,255,0.2)';
        userInfo.style.borderRadius = '12px';
        userInfo.style.color = 'white';
        header.appendChild(userInfo);
    }
    
    if (currentUser) {
        userInfo.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>👤 ${currentUser.fullName}</strong><br>
                    <small>${currentUser.email}</small>
                    ${currentUser.role === 'admin' ? '<span style="background: gold; color: black; padding: 2px 8px; border-radius: 12px; margin-left: 10px;">Admin</span>' : ''}
                </div>
                <button onclick="logout()" style="background: rgba(255,255,255,0.3); border: none; color: white; padding: 8px 16px; border-radius: 8px; cursor: pointer;">
                    Logout
                </button>
            </div>
        `;
    } else {
        userInfo.innerHTML = '';
    }
}

// Logout function
function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    updateUserUI();
    addNotification('info', 'Logged Out', 'You have been logged out');
}

// Load user messages
async function loadUserMessages(userId) {
    if (!authToken) return;
    
    try {
        const response = await fetch(`${API_URL}/api/messages/user/${userId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            messages = result.data;
            updateMessagesDisplay();
        }
    } catch (error) {
        console.error('Error loading user messages:', error);
    }
}

// Load all messages (Admin only)
async function loadAllMessages() {
    if (!currentUser || currentUser.role !== 'admin') return;
    
    try {
        const response = await fetch(`${API_URL}/api/admin/messages`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            messages = result.data;
            updateMessagesDisplay();
            addNotification('info', 'Admin Mode', `Loaded ${result.total} total messages`);
        }
    } catch (error) {
        console.error('Error loading all messages:', error);
    }
}

// Update contact form to include userId if logged in
function updateContactForm() {
    const contactForm = document.getElementById('contact-form');
    if (contactForm && currentUser) {
        // Add hidden userId field
        let userIdField = document.getElementById('user-id-field');
        if (!userIdField) {
            userIdField = document.createElement('input');
            userIdField.type = 'hidden';
            userIdField.id = 'user-id-field';
            userIdField.name = 'userId';
            contactForm.appendChild(userIdField);
        }
        userIdField.value = currentUser._id;
        
        // Pre-fill name and email if logged in
        const nameField = document.getElementById('name');
        const emailField = document.getElementById('email');
        if (nameField && !nameField.value) nameField.value = currentUser.fullName;
        if (emailField && !emailField.value) emailField.value = currentUser.email;
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', async () => {
    await initializeElementSdk();
    await initializeDataSdk();
    
    // Registration form
    const regForm = document.getElementById('registration-form');
    if (regForm) {
        regForm.addEventListener('submit', handleRegister);
    }
    
    // Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Contact form
    const contactForm = document.getElementById('contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', handleFormSubmit);
    }
    
    // Update UI based on stored user
    if (localStorage.getItem('token')) {
        try {
            // Verify token and get user profile
            const response = await fetch(`${API_URL}/api/profile`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            const result = await response.json();
            if (result.success) {
                currentUser = result.data;
                authToken = localStorage.getItem('token');
                updateUserUI();
                updateContactForm();
                
                // Load appropriate messages
                if (currentUser.role === 'admin') {
                    loadAllMessages();
                } else {
                    loadUserMessages(currentUser._id);
                }
            }
        } catch (error) {
            console.error('Error loading profile:', error);
            logout();
        }
    }
});

// Update showMessage function to support custom messages
function showMessage(messageId, customMessage = null) {
    hideAllMessages();
    const messageEl = document.getElementById(messageId);
    if (messageEl) {
        if (customMessage) {
            if (messageId === 'success-message') {
                messageEl.innerHTML = '✅ ' + customMessage;
            } else if (messageId === 'error-message') {
                messageEl.innerHTML = '❌ ' + customMessage;
            }
        }
        messageEl.style.display = 'block';
        setTimeout(() => {
            messageEl.style.display = 'none';
        }, 5000);
    }
}