(function () {
    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('loginEmail');
    const passwordInput = document.getElementById('loginPassword');
    const submitButton = document.querySelector('[data-login-submit]');
    const errorBox = document.getElementById('loginError');

    function setError(message) {
        if (!errorBox) {
            return;
        }
        if (message) {
            errorBox.textContent = message;
            errorBox.hidden = false;
        } else {
            errorBox.textContent = '';
            errorBox.hidden = true;
        }
    }

    function setSubmitting(state) {
        if (!submitButton) {
            return;
        }
        submitButton.disabled = state;
        const label = submitButton.querySelector('.login-submit__label');
        if (label) {
            label.textContent = state ? 'Signing in…' : 'Sign in';
        }
    }

    function handleSubmit(event) {
        if (!form || !emailInput || !passwordInput) {
            return;
        }
        const username = emailInput.value.trim();
        const password = passwordInput.value.trim();
        if (!username || !password) {
            event.preventDefault();
            setError('Email and password are required.');
            (username ? passwordInput : emailInput).focus();
            return;
        }

        setError('');
        setSubmitting(true);
    }

    function init() {
        const serverError = errorBox?.dataset?.serverError;
        if (serverError) {
            setError(serverError);
        }
        form?.addEventListener('submit', handleSubmit);
        emailInput?.focus();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
