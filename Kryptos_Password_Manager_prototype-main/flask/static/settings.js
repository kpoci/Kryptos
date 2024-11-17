$(document).ready(function() {
    console.log("Settings JavaScript loaded.");

    // Change Email Form Submission
    $('#changeEmailForm').on('submit', function(event) {
        event.preventDefault();
        let newEmail = $('#newEmail').val();
        $.ajax({
            url: '/change_email',
            type: 'POST',
            data: { email: newEmail },
            success: function(response) {
                alert(response.message || 'Email updated successfully!');
                $('#changeEmailModal').modal('hide');
            },
            error: function(error) {
                alert('Failed to update email. Please try again.');
            }
        });
    });

    // Change Username Form Submission
    $('#changeUsernameForm').on('submit', function(event) {
        event.preventDefault();
        let newUsername = $('#newUsername').val();
        $.ajax({
            url: '/change_username',
            type: 'POST',
            data: { username: newUsername },
            success: function(response) {
                alert(response.message || 'Username updated successfully!');
                $('#changeUsernameModal').modal('hide');
            },
            error: function(error) {
                alert('Failed to update username. Please try again.');
            }
        });
    });

    // Change Password Form Submission
    $('#changePasswordForm').on('submit', function(event) {
        event.preventDefault();
        let newPassword = $('#newPassword').val();
        $.ajax({
            url: '/change_password',
            type: 'POST',
            data: { password: newPassword },
            success: function(response) {
                alert(response.message || 'Password updated successfully!');
                $('#changePasswordModal').modal('hide');
            },
            error: function(error) {
                alert('Failed to update password. Please try again.');
            }
        });
    });

    // Add similar functions for other settings if needed
    // Change Master Password Form Submission
    $('#changeMasterPasswordForm').on('submit', function(event) {
        event.preventDefault();
        let currentMasterPassword = $('#currentMasterPassword').val();
        let newMasterPassword = $('#newMasterPassword').val();
        let confirmMasterPassword = $('#confirmMasterPassword').val();

        if (newMasterPassword !== confirmMasterPassword) {
            alert('New master passwords do not match.');
            return;
        }

        $.ajax({
            url: '/change_master_password',
            type: 'POST',
            data: {
                current_master_password: currentMasterPassword,
                new_master_password: newMasterPassword
            },
            success: function(response) {
                alert(response.message || 'Master password updated successfully!');
                $('#changeMasterPasswordModal').modal('hide');
                $('#changeMasterPasswordForm')[0].reset();
            },
            error: function(error) {
                alert(error.responseJSON.message || 'Failed to update master password. Please try again.');
            }
        });
    });
    // Idle Logout Time Form Submission
    $('#idleLogoutTimeForm').on('submit', function(event) {
        event.preventDefault();
        let idleTime = $('#idleTime').val();

        $.ajax({
            url: '/set_idle_logout_time',
            type: 'POST',
            data: { idle_time: idleTime },
            success: function(response) {
                alert(response.message || 'Idle logout time updated successfully!');
                $('#idleLogoutTimeModal').modal('hide');
                $('#idleLogoutTimeForm')[0].reset();
            },
            error: function(error) {
                alert(error.responseJSON.message || 'Failed to update idle logout time. Please try again.');
            }
        });
    });
    // Password Generator Settings Form Submission
    $('#passwordGeneratorSettingsForm').on('submit', function(event) {
        event.preventDefault();
        let passwordLength = $('#passwordLength').val();
        let includeUppercase = $('#includeUppercase').is(':checked');
        let includeLowercase = $('#includeLowercase').is(':checked');
        let includeNumbers = $('#includeNumbers').is(':checked');
        let includeSymbols = $('#includeSymbols').is(':checked');

        $.ajax({
            url: '/update_password_generator_settings',
            type: 'POST',
            data: {
                password_length: passwordLength,
                include_uppercase: includeUppercase,
                include_lowercase: includeLowercase,
                include_numbers: includeNumbers,
                include_symbols: includeSymbols
            },
            success: function(response) {
                alert(response.message || 'Password generator settings updated successfully!');
                $('#passwordGeneratorSettingsModal').modal('hide');
                $('#passwordGeneratorSettingsForm')[0].reset();
            },
            error: function(error) {
                alert(error.responseJSON.message || 'Failed to update password generator settings. Please try again.');
            }
        });
    });

});
