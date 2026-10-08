/**
 * PhishGuard — User Login Interactive Scripts (Page 3)
 * 
 * Features:
 * 1. Password visibility toggle (show / hide password)
 * 2. Mobile navigation toggle support
 * 3. Client-side input validation and dynamic error clearing
 * 4. Smooth AJAX submission with loading indicator
 * 5. Secure redirect to /dashboard upon successful authentication
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const loginForm = document.getElementById('loginForm');
  const loginAlert = document.getElementById('loginAlert');
  const loginAlertText = document.getElementById('loginAlertText');
  const submitBtn = document.getElementById('submitBtn');

  // Inputs
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');

  // Error containers
  const emailError = document.getElementById('emailError');
  const passwordError = document.getElementById('passwordError');

  // Password visibility toggle
  const togglePasswordBtn = document.getElementById('togglePassword');

  // Mobile menu button
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const navMenu = document.getElementById('navMenu');

  // --------------------------------------------------------------------------
  // 1. Mobile Menu Toggle
  // --------------------------------------------------------------------------
  if (mobileMenuBtn && navMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      const isExpanded = mobileMenuBtn.getAttribute('aria-expanded') === 'true';
      mobileMenuBtn.setAttribute('aria-expanded', !isExpanded);
      mobileMenuBtn.classList.toggle('active');
      navMenu.classList.toggle('open');
      navMenu.classList.toggle('active');
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', (event) => {
      if (!navMenu.contains(event.target) && !mobileMenuBtn.contains(event.target)) {
        navMenu.classList.remove('open');
        navMenu.classList.remove('active');
        mobileMenuBtn.classList.remove('active');
        mobileMenuBtn.setAttribute('aria-expanded', 'false');
      }
    });

    // Auto-close mobile menu when a navigation link is clicked
    const navLinks = navMenu.querySelectorAll('.nav-link, .btn');
    navLinks.forEach((link) => {
      link.addEventListener('click', () => {
        navMenu.classList.remove('open');
        navMenu.classList.remove('active');
        mobileMenuBtn.classList.remove('active');
        mobileMenuBtn.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // --------------------------------------------------------------------------
  // 2. Password Visibility Toggle
  // --------------------------------------------------------------------------
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';

      togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      
      const eyeIcon = togglePasswordBtn.querySelector('.icon-eye');
      const eyeOffIcon = togglePasswordBtn.querySelector('.icon-eye-off');
      if (eyeIcon && eyeOffIcon) {
        eyeIcon.style.display = isPassword ? 'none' : 'block';
        eyeOffIcon.style.display = isPassword ? 'block' : 'none';
      }
    });
  }

  // --------------------------------------------------------------------------
  // 3. Error Helpers
  // --------------------------------------------------------------------------
  const showFieldError = (inputEl, errorEl, message) => {
    if (!inputEl || !errorEl) return;
    inputEl.classList.add('is-invalid');
    inputEl.setAttribute('aria-invalid', 'true');
    
    const errorTextSpan = errorEl.querySelector('.error-text');
    if (errorTextSpan) {
      errorTextSpan.textContent = message;
    } else {
      errorEl.textContent = message;
    }
    errorEl.classList.add('visible');
  };

  const clearFieldError = (inputEl, errorEl) => {
    if (!inputEl || !errorEl) return;
    inputEl.classList.remove('is-invalid');
    inputEl.removeAttribute('aria-invalid');
    errorEl.classList.remove('visible');
  };

  const showTopAlert = (message, type = 'danger') => {
    if (!loginAlert || !loginAlertText) return;
    loginAlert.className = `form-alert alert-${type} visible`;
    loginAlertText.textContent = message;
    loginAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const hideTopAlert = () => {
    if (!loginAlert) return;
    loginAlert.classList.remove('visible');
  };

  // --------------------------------------------------------------------------
  // 4. Live Feedback Listeners
  // --------------------------------------------------------------------------
  emailInput?.addEventListener('input', () => {
    if (emailInput.classList.contains('is-invalid')) {
      clearFieldError(emailInput, emailError);
    }
    hideTopAlert();
  });

  passwordInput?.addEventListener('input', () => {
    if (passwordInput.classList.contains('is-invalid')) {
      clearFieldError(passwordInput, passwordError);
    }
    hideTopAlert();
  });

  // --------------------------------------------------------------------------
  // 5. Form Submission Handler
  // --------------------------------------------------------------------------
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideTopAlert();

      const emailVal = emailInput.value.trim();
      const passwordVal = passwordInput.value;

      let isValid = true;

      // Validate email
      if (!emailVal) {
        showFieldError(emailInput, emailError, 'Please enter your email address.');
        isValid = false;
      } else {
        clearFieldError(emailInput, emailError);
      }

      // Validate password
      if (!passwordVal) {
        showFieldError(passwordInput, passwordError, 'Please enter your password.');
        isValid = false;
      } else {
        clearFieldError(passwordInput, passwordError);
      }

      if (!isValid) {
        if (!emailVal) emailInput.focus();
        else if (!passwordVal) passwordInput.focus();
        return;
      }

      // Enter loading state
      submitBtn.classList.add('is-loading');
      submitBtn.disabled = true;

      const payload = {
        email: emailVal.toLowerCase(),
        password: passwordVal
      };

      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success) {
          // Success State: redirect to dashboard
          window.location.href = data.redirect_url || '/dashboard';
        } else {
          // Failure handling
          submitBtn.classList.remove('is-loading');
          submitBtn.disabled = false;

          if (data.errors) {
            if (data.errors.email) showFieldError(emailInput, emailError, data.errors.email);
            if (data.errors.password) showFieldError(passwordInput, passwordError, data.errors.password);
            if (data.errors.general) showTopAlert(data.errors.general, 'danger');
          } else {
            showTopAlert(data.message || 'Invalid email or password.', 'danger');
          }
        }
      } catch (err) {
        // Network / Unexpected Client Error
        submitBtn.classList.remove('is-loading');
        submitBtn.disabled = false;
        showTopAlert('Unable to connect to the server. Please verify your connection and try again.', 'danger');
      }
    });
  }
});
