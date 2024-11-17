
document.getElementById('key_id').addEventListener('change', function() {
    document.getElementById('new_key_field').style.display = (this.value === 'new') ? 'block' : 'none';
    $(document).ready(function() {
        fetchContainers();
    })
        

        $('#keyVaultButton').click(function() {
            $('#masterPasswordModal').modal('show');
        });
    
        // Handle Master Password Form Submission
        $('#masterPasswordForm').on('submit', function(event) {
            event.preventDefault();  // Prevent the default form submission
            var masterPassword = $('#masterPassword').val();
    
            $.ajax({
                url: '/verify_master_password',
                type: 'POST',
                data: {masterPassword: masterPassword},
                success: function(response) {
                    if (response.success) {
                        $('#masterPasswordModal').modal('hide');  // Hide the password modal
                        fetchAndDisplayKeys();  // Fetch and display keys if password is verified
                    } else {
                        alert(response.message || 'Incorrect master password. Please try again.');
                    }
                },
                error: function() {
                    alert('Error verifying password. Please try again later.');
                }
            });
        });
    
        // Function to fetch and display keys
        function fetchAndDisplayKeys() {
            $.ajax({
                url: '/fetch_keys',
                type: 'GET',
                success: function(response) {
                    if (response.success) {
                        var keysHTML = '';
                        response.keys.forEach(function(key) {
                            keysHTML += `<tr>
                                <td>${key.key_name}</td>
                                <td>${key.key}</td>
                            </tr>`;
                        });
                        $('#keysTableBody').html(keysHTML);
                        $('#keysModal').modal('show');
                    } else {
                        alert(response.message || 'No keys found.');
                    }
                },
                error: function() {
                    alert('Failed to fetch keys.');
                }
            });
        }

    $(document).ready(function() {
        $('#logoutButton').on('click', function() {
            $.ajax({
                url: '/logout',
                type: 'GET',
                success: function(response) {
                    window.location.href = '/';  // Redirect to the home or login page
                },
                error: function(error) {
                    console.error('Error:', error);
                    alert('Error logging out. Please try again.');
                }
            });
        });
    });
})