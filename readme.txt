// Forget Passsword Process
#1. User click on forget password
#2. Create a reset token (string) and save in your database
#3. Send reset token to user email in the form of a link
#4. When user clicks the link, compare the reset token in 
    the link with that save in the database
#5. if they match, change reset the user password

//Forget Password Steps
#1. Create a forget password route
#2. Create Token model
#3. Create Email sender
#4. Create a controller function