# COMP1004Project

This project final website is a basic password manager, utilising local storage to save passwords enetered by the user in encrypted format. The website user can also edit, delete and display these passwords that are stored here. This page has 6 main sections:

1. Saving of passwords to local storage:
   - This first section, as the name suggests, allows the client to save passwords to local storage, asking for the website name, a username or email, and a password to be entered. The password is then encrypted using the Subtle.Crypto library before being stored in local        storage with the other credential components.

2. Editing of passwords:
   - Secondly, the user can edit saved passwords using this function, which asks for a website name to be inputted, followed by asking whether the username and password need to be edited, or just one of the above. The new credentials can then be entered and this is then          re-encrypted and hashed, before storing back to local storage under the original key.

3. Deletion of passwords:
   - Furthermore, passwords stored in local storage can be altered by inputting the website name used as the key. The program then finds the corresponding data and removes it using the given key.
  
4. Display of passwords:
   - The user has the option in this menu to either
       - Display all passwords saved - this outputs in a table, showing the website name, username/email, and passwords in respective columns
       - Enter a specific website name to show a single password - the username and password are then outputted to the user.
    
5. Generate a password:
   - This function allows requirements to be set by the client to change what the password contains (different types of characters and lengths).
   - The password is then generated using a fixed set of characters to meet these requirements, and outputted on the main site.
  
6. Checking of a password:
   - Finally, the user has the option to input a password that they have made, and the program checks it against the basic password requirements. If the password meets these requirements, the user is told the password is a good password, and can then save it using the above methods. The basic requirements are:
       - 8 Characters
       - Upper and Lower Case Characters
       - Numbers
       - Special Characters

In order to use the site, a master username and password must be created, alongisde answering 2 recovery questions which are used if the password is forgotten to reset it. Once this is done, the user can login and utilise all the other features documented above. Once logged in, all passwords can be accessed. The data can be all cleared if necessary using the clear storage button located in the top right of the software. 

The settings page can be used to change the background colour of the pages, allowing the page to be accessible to all. This can once again be accessed using the button in the top right of the software. 
