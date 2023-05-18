document.addEventListener("DOMContentLoaded", function() {

  // Select the login button
  const loginButton = document.querySelector("[data-modal-toggle='authentication-modal']");

  // Listen for a click event on the login button
  loginButton.addEventListener('click', function() {
    
    // Display the login modal when the button is clicked
    const loginModal = document.getElementById('authentication-modal');
    loginModal.style.display = "block";
    
    // Select the form inside the modal
    const loginForm = loginModal.querySelector('form');
    
    // Listen for a submit event on the form
    loginForm.addEventListener('submit', function(event) {
      
      // Prevent the form from submitting normally
      event.preventDefault();
      
      // Get the email and password
      const email = loginForm.querySelector('input[name="email"]').value;
      const password = loginForm.querySelector('input[name="password"]').value;
      
      // Now you can send the email and password to the server
      // for processing (e.g., via fetch or XMLHttpRequest)
      console.log(`Email: ${email}, Password: ${password}`);
    });
  });
});

