const hideOrShowPasswords = () => {
    const passwords = document.getElementsByClassName('passwords-form-value');
    const buttonText = document.getElementById('show-hide');
    buttonText.innerHTML = buttonText.innerHTML === 'pokaż' ? 'ukryj' : 'pokaż';

    for (let i = 0; i < passwords.length; i++) {
        passwords[i].type = passwords[i].type === 'text' ? 'password' : 'text';
    }
};
