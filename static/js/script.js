document.getElementById("authentication-modal").addEventListener("submit", function(event){
  event.preventDefault();

  let user = document.getElementById('username').value;
  let pass = document.getElementById('password').value;
  
  // Perform a fetch to your Flask API
  fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: user,
      password: pass
    })
  }).then(response => response.json())
    .then(data => {
      if(data.status === 'success'){
        // Login was successful
        alert('Logged in successfully!');
      } else {
        // Login failed
        alert('Error: ' + data.message);
      }
    })
    .catch((error) => {
      console.error('Error:', error);
    });
});
