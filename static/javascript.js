function logout() {
    // Confirm if the user really wants to log out
    const confirmLogout = confirm("Are you sure you want to log out?");
    if (confirmLogout) {
      localStorage.removeItem("token"); // Remove JWT token
      window.location.href = "/frontend/login.html";

    }
  }
  

  document.getElementById('contactForm').addEventListener('submit', async function(e) {
    e.preventDefault(); // Prevent default form submission
    const formData = new FormData(this);
    
    try {
      const response = await fetch('/contact', {
        method: 'POST',
        body: formData
      });
      
      const result = await response.json();
      
      if(response.ok) {
        document.getElementById('successMsg').style.display = 'block';
        document.getElementById('errorMsg').style.display = 'none';
        // Optionally, clear the form fields
        this.reset();
      } else {
        throw new Error(result.message || 'Unknown error');
      }
    } catch (error) {
      document.getElementById('errorMsg').style.display = 'block';
      document.getElementById('successMsg').style.display = 'none';
      console.error('Error:', error);
    }
  });