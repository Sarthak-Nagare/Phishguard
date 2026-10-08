/**
 * PhishGuard — User Registration Interactive Scripts (Page 2)
 * 
 * Features:
 * 1. Comprehensive client-side form validation (name, email, password, confirm password)
 * 2. Real-time input validation and error clearing on input
 * 3. Password visibility toggle (show / hide password)
 * 4. Password length indicator
 * 5. Smooth AJAX submission with loading state & graceful fallback
 * 6. Dynamic success presentation with direct link to Page 3 Login
 */

document.addEventListener('DOMContentLoaded', () => {
  // Form and card containers
  const registerForm = document.getElementById('registerForm');
  const formCard = document.getElementById('formCard');
  const successCard = document.getElementById('successCard');
  const formAlert = document.getElementById('formAlert');
  const formAlertText = document.getElementById('formAlertText');
  const submitBtn = document.getElementById('submitBtn');

  // Input elements
  const nameInput = document.getElementById('name');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirm_password');

  // Error message elements
  const nameError = document.getElementById('nameError');
  const emailError = document.getElementById('emailError');
  const passwordError = document.getElementById('passwordError');
  const confirmPasswordError = document.getElementById('confirmPasswordError');

  // Password requirement indicator
  const reqLength = document.getElementById('reqLength');

  // Show/Hide password toggles
  const togglePasswordBtn = document.getElementById('togglePassword');
  const toggleConfirmPasswordBtn = document.getElementById('toggleConfirmPassword');

  // Regex pattern for email validation
  const EMAIL_PATTERN = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;

  // --------------------------------------------------------------------------
  // 1. Password Visibility Toggle Handlers
  // --------------------------------------------------------------------------
  const setupPasswordToggle = (toggleBtn, inputEl) => {
    if (!toggleBtn || !inputEl) return;

    toggleBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const isPassword = inputEl.type === 'password';
      inputEl.type = isPassword ? 'text' : 'password';

      // Update button aria label and SVG icon
      toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      
      const eyeIcon = toggleBtn.querySelector('.icon-eye');
      const eyeOffIcon = toggleBtn.querySelector('.icon-eye-off');
      if (eyeIcon && eyeOffIcon) {
        eyeIcon.style.display = isPassword ? 'none' : 'block';
        eyeOffIcon.style.display = isPassword ? 'block' : 'none';
      }
    });
  };

  setupPasswordToggle(togglePasswordBtn, passwordInput);
  setupPasswordToggle(toggleConfirmPasswordBtn, confirmPasswordInput);

  // --------------------------------------------------------------------------
  // 2. Field Error Helpers
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
    if (!formAlert || !formAlertText) return;
    formAlert.className = `form-alert alert-${type} visible`;
    formAlertText.textContent = message;
    formAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const hideTopAlert = () => {
    if (!formAlert) return;
    formAlert.classList.remove('visible');
  };

  // --------------------------------------------------------------------------
  // 3. Validation Logic per Field
  // --------------------------------------------------------------------------
  const validateName = () => {
    const value = nameInput.value.trim();
    if (!value) {
      showFieldError(nameInput, nameError, 'Full name cannot be empty.');
      return false;
    }
    if (value.length < 2) {
      showFieldError(nameInput, nameError, 'Full name must be at least 2 characters long.');
      return false;
    }
    if (value.length > 100) {
      showFieldError(nameInput, nameError, 'Full name cannot exceed 100 characters.');
      return false;
    }
    clearFieldError(nameInput, nameError);
    return true;
  };

  const validateEmail = () => {
    const value = emailInput.value.trim();
    if (!value) {
      showFieldError(emailInput, emailError, 'Email address cannot be empty.');
      return false;
    }
    if (!EMAIL_PATTERN.test(value)) {
      showFieldError(emailInput, emailError, 'Please enter a valid email format (e.g. name@example.com).');
      return false;
    }
    clearFieldError(emailInput, emailError);
    return true;
  };

  const validatePassword = () => {
    const value = passwordInput.value;
    if (!value) {
      showFieldError(passwordInput, passwordError, 'Password cannot be empty.');
      if (reqLength) reqLength.classList.remove('met');
      return false;
    }
    if (value.length < 8) {
      showFieldError(passwordInput, passwordError, 'Password must be at least 8 characters long.');
      if (reqLength) reqLength.classList.remove('met');
      return false;
    }
    if (value.length > 128) {
      showFieldError(passwordInput, passwordError, 'Password cannot exceed 128 characters.');
      return false;
    }

    if (reqLength) reqLength.classList.add('met');
    clearFieldError(passwordInput, passwordError);

    // If confirm password already has a value, re-check match
    if (confirmPasswordInput.value) {
      validateConfirmPassword();
    }
    return true;
  };

  const validateConfirmPassword = () => {
    const passwordVal = passwordInput.value;
    const confirmVal = confirmPasswordInput.value;

    if (!confirmVal) {
      showFieldError(confirmPasswordInput, confirmPasswordError, 'Please confirm your password.');
      return false;
    }
    if (confirmVal !== passwordVal) {
      showFieldError(confirmPasswordInput, confirmPasswordError, 'Passwords do not match. Please verify.');
      return false;
    }
    clearFieldError(confirmPasswordInput, confirmPasswordError);
    return true;
  };

  // --------------------------------------------------------------------------
  // 4. Live Feedback Listeners
  // --------------------------------------------------------------------------
  nameInput?.addEventListener('input', () => {
    if (nameInput.classList.contains('is-invalid')) validateName();
  });
  nameInput?.addEventListener('blur', validateName);

  emailInput?.addEventListener('input', () => {
    if (emailInput.classList.contains('is-invalid')) validateEmail();
  });
  emailInput?.addEventListener('blur', validateEmail);

  passwordInput?.addEventListener('input', () => {
    // Update live 8-char indicator
    if (passwordInput.value.length >= 8) {
      if (reqLength) reqLength.classList.add('met');
    } else {
      if (reqLength) reqLength.classList.remove('met');
    }

    if (passwordInput.classList.contains('is-invalid')) validatePassword();
  });
  passwordInput?.addEventListener('blur', validatePassword);

  confirmPasswordInput?.addEventListener('input', () => {
    if (confirmPasswordInput.classList.contains('is-invalid')) validateConfirmPassword();
  });
  confirmPasswordInput?.addEventListener('blur', validateConfirmPassword);

  // --------------------------------------------------------------------------
  // 5. Form Submission Handler
  // --------------------------------------------------------------------------
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideTopAlert();

      // Run full suite of validations
      const isNameValid = validateName();
      const isEmailValid = validateEmail();
      const isPasswordValid = validatePassword();
      const isConfirmValid = validateConfirmPassword();

      if (!isNameValid || !isEmailValid || !isPasswordValid || !isConfirmValid) {
        // Focus first invalid element
        if (!isNameValid) nameInput.focus();
        else if (!isEmailValid) emailInput.focus();
        else if (!isPasswordValid) passwordInput.focus();
        else if (!isConfirmValid) confirmPasswordInput.focus();
        return;
      }

      // Enter loading state
      submitBtn.classList.add('is-loading');
      submitBtn.disabled = true;

      const payload = {
        name: nameInput.value.trim(),
        email: emailInput.value.trim().toLowerCase(),
        password: passwordInput.value,
        confirm_password: confirmPasswordInput.value
      };

      try {
        const response = await fetch('/register', {
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
          // Success State: show success card
          if (formCard && successCard) {
            formCard.style.display = 'none';
            successCard.classList.add('visible');
            window.scrollTo({ top: 0, behavior: 'smooth' });
          } else {
            showTopAlert(data.message || 'Account created successfully! Redirecting...', 'success');
            setTimeout(() => {
              window.location.href = data.redirect_url || '/login';
            }, 1500);
          }
        } else {
          // Failure handling
          submitBtn.classList.remove('is-loading');
          submitBtn.disabled = false;

          if (data.errors) {
            if (data.errors.name) showFieldError(nameInput, nameError, data.errors.name);
            if (data.errors.email) {
              showFieldError(emailInput, emailError, data.errors.email);
              emailInput.focus();
            }
            if (data.errors.password) showFieldError(passwordInput, passwordError, data.errors.password);
            if (data.errors.confirm_password) showFieldError(confirmPasswordInput, confirmPasswordError, data.errors.confirm_password);
            if (data.errors.general) showTopAlert(data.errors.general, 'danger');
          } else {
            showTopAlert(data.message || 'Registration failed. Please check the form and try again.', 'danger');
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
