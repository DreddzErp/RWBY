// Password visibility toggle
document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    this.textContent = type === 'password' ? '👁' : '🙈'; // Change icon based on visibility
});

// Client-side validation and form submission
document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    // Clear previous error messages
    document.getElementById('emailError').textContent = '';
    document.getElementById('passwordError').textContent = '';
    document.getElementById('formError').textContent = '';

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    let hasError = false;

    // Simple email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        document.getElementById('emailError').textContent = 'Please enter a valid email address.';
        hasError = true;
    }

    // Password validation (minimum 8 characters)
    if (password.length < 8) {
        document.getElementById('passwordError').textContent = 'Password must be at least 8 characters long.';
        hasError = true;
    }

    if (hasError) {
        return; // Stop form submission if there are validation errors
    }

    // Fetch login request
    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include' // Include credentials for session cookies
    })
    .then(response => {
        return response.json().then(data => {
            if (!response.ok) {
                throw new Error(data.message || 'Login failed.'); // Handle error messages from the server
            }
            return data;
        });
    })
    .then(data => {
        if (data.success) {
            // Check user role and redirect accordingly
            if (data.role === 'admin') {
                window.location.href = '/admin_dashboard.html';
            } else {
                window.location.href = '/dashboard.html';
            }
        } else {
            // Display error message
            document.getElementById('formError').textContent = data.message;
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        document.getElementById('formError').textContent = error.message || 'An error occurred during login.';
    });

    
});
