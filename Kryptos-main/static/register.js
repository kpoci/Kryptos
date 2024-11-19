$(document).ready(function () {
    // Password Fields
    const passwordFields = [
        {
            input: $('#password'),
            meter: $('#password-strength-meter'),
            text: $('#password-strength-text'),
            generateButton: $('#generate-password'),
            showPasswordCheckbox: $('#show-password')
        },
        {
            input: $('#master_pass'),
            meter: $('#master-pass-strength-meter'),
            text: $('#master-pass-strength-text'),
            generateButton: $('#generate-master-pass'),
            showPasswordCheckbox: $('#show-master-pass')
        },
        {
            input: $('#security_password'),
            meter: $('#security-pass-strength-meter'),
            text: $('#security-pass-strength-text'),
            generateButton: $('#generate-security-pass'),
            showPasswordCheckbox: $('#show-security-pass')
        }
    ];

    passwordFields.forEach(field => {
        field.input.on('input', function () {
            const val = field.input.val();
            const strength = getPasswordStrength(val);

            // Update the password strength meter
            field.meter.val(strength.score);

            // Update the text indicator
            if (val !== "") {
                const strengthLevels = ["Very Weak", "Weak", "Fair", "Good", "Strong"];
                field.text.text("Strength: " + strengthLevels[strength.score]);
            } else {
                field.text.text("");
            }
        });

        field.generateButton.on('click', function () {
            const password = generatePassword();
            field.input.val(password).trigger('input');
        });

        // Show Password Toggle
        field.showPasswordCheckbox.on('change', function () {
            if (field.showPasswordCheckbox.is(':checked')) {
                field.input.attr('type', 'text');
            } else {
                field.input.attr('type', 'password');
            }
        });
    });

    function getPasswordStrength(password) {
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^\w\s]/.test(password)) score++;  // Allow spaces, require special characters excluding spaces
        return { score: score };
    }

    function generatePassword() {
        const length = 12;
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        // Include space in the charset
        const charsetWithSpace = charset + " ";
        let password = "";
        for (let i = 0, n = charsetWithSpace.length; i < length; ++i) {
            password += charsetWithSpace.charAt(Math.floor(Math.random() * n));
        }
        return password;
    }
});
