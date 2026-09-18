/* =========================================================
   TRACE MAIL AI — AUTHENTICATION CONTROLLER
   Backend is the source of truth for authentication + role.
   ========================================================= */


/* =========================================================
   1. DISPLAY AUTHENTICATED USER
   ========================================================= */

function displayAuthenticatedUser(user){

  const nameEl = document.getElementById('tmUserName');
  const emailEl = document.getElementById('tmUserEmail');
  const avatarEl = document.getElementById('tmUserAvatar');

  if(nameEl){
    nameEl.textContent = user.name || 'TraceMail User';
  }

  if(emailEl){
    emailEl.textContent = user.email || '';
  }

  if(avatarEl){

    if(user.picture){

      avatarEl.innerHTML =
        '<img src="' +
        user.picture +
        '" alt="Profile">';

    }else{

      const initial =
        (user.name || user.email || 'U')
        .trim()
        .charAt(0)
        .toUpperCase();

      avatarEl.textContent = initial;
    }
  }
}


/* =========================================================
   2. APPLY AUTHENTICATED USER
   ========================================================= */

function unlockTraceMail(source, user){

  /*
    IMPORTANT:
    The role comes from the backend.

    We do NOT trust localStorage for authentication
    or authorization.
  */

  if(user && user.role){

    setRole(user.role, false);

  }

  if(user){

    localStorage.setItem(
      'tmUserName',
      user.name || ''
    );

    localStorage.setItem(
      'tmUserEmail',
      user.email || ''
    );

  }

  if(source){

    localStorage.setItem(
      'tmIntakeSource',
      source
    );

  }

  sessionStorage.setItem(
    'tmAuthenticated',
    '1'
  );

  const gate =
    document.getElementById('authGate');

  if(gate){

    gate.classList.add('hidden');

    gate.setAttribute(
      'aria-hidden',
      'true'
    );

  }

  document.body.classList.remove(
    'authLocked'
  );

  go('dashboard');

  toast(
    source === 'eml'
      ? 'EML evidence loaded — welcome to your workspace'
      : 'Welcome to TraceMail AI'
  );
}


/* =========================================================
   3. EMAIL + PASSWORD LOGIN
   ========================================================= */

async function authEmailLogin(){

  const emailEl =
    document.getElementById('authEmail');

  const passwordEl =
    document.getElementById('authPassword');

  const email =
    (emailEl?.value || '').trim();

  const password =
    passwordEl?.value || '';


  /* ---------- Frontend validation ---------- */

  if(
    !email ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ){

    toast('Enter a valid work email');

    emailEl?.focus();

    return;
  }


  if(!password){

    toast('Enter your password');

    passwordEl?.focus();

    return;
  }


  /* ---------- Backend login ---------- */

  try{

    const response = await fetch(
      '/auth/login',
      {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json'
        },

        credentials: 'include',

        body: JSON.stringify({
          email: email,
          password: password
        })
      }
    );


    const data = await response.json()
      .catch(() => ({}));


    /* ---------- Login failed ---------- */

    if(!response.ok){

      toast(
        data.detail ||
        data.message ||
        'Login failed'
      );

      return;
    }


    /* ---------- Login successful ---------- */

    if(data.user){

      displayAuthenticatedUser(
        data.user
      );

      unlockTraceMail(
        'email',
        data.user
      );

    }else{

      /*
        Even if login succeeds without
        returning a user object, verify
        the backend session.
      */

      await checkBackendAuthentication();

    }

  }catch(error){

    console.error(
      'Email login failed:',
      error
    );

    toast(
      'Unable to connect to TraceMail server'
    );

  }

}


/* =========================================================
   4. REGISTRATION
   ========================================================= */

async function authRegister(){

  const nameEl =
    document.getElementById('registerName');

  const emailEl =
    document.getElementById('registerEmail');

  const passwordEl =
    document.getElementById('registerPassword');

  const confirmEl =
    document.getElementById('registerConfirmPassword');

  const roleEl =
    document.getElementById('registerRole');


  const name =
    (nameEl?.value || '').trim();

  const email =
    (emailEl?.value || '').trim();

  const password =
    passwordEl?.value || '';

  const confirmPassword =
    confirmEl?.value || '';

  const role =
    roleEl?.value || '';


  /* ---------- Validation ---------- */

  if(!name){

    toast('Enter your full name');

    nameEl?.focus();

    return;
  }


  if(
    !email ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ){

    toast('Enter a valid work email');

    emailEl?.focus();

    return;
  }


  if(!password){

    toast('Create a password');

    passwordEl?.focus();

    return;
  }


  if(password.length < 8){

    toast(
      'Password must be at least 8 characters'
    );

    passwordEl?.focus();

    return;
  }


  if(password !== confirmPassword){

    toast('Passwords do not match');

    confirmEl?.focus();

    return;
  }


  if(
    !['viewer', 'analyst', 'admin'].includes(role)
  ){

    toast('Select a valid role');

    roleEl?.focus();

    return;
  }


  /* ---------- Backend registration ---------- */

  try{

    const response = await fetch(
      '/auth/register',
      {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json'
        },

        credentials: 'include',

        body: JSON.stringify({
          name: name,
          email: email,
          password: password,
          role: role
        })
      }
    );


    const data = await response.json()
      .catch(() => ({}));


    /* ---------- Registration failed ---------- */

    if(!response.ok){

      toast(
        data.detail ||
        data.message ||
        'Registration failed'
      );

      return;
    }


    /* ---------- Registration successful ---------- */

    if(data.user){

      displayAuthenticatedUser(
        data.user
      );

      unlockTraceMail(
        'register',
        data.user
      );

    }else{

      await checkBackendAuthentication();

    }

  }catch(error){

    console.error(
      'Registration failed:',
      error
    );

    toast(
      'Unable to connect to TraceMail server'
    );

  }

}


/* =========================================================
   5. GOOGLE OAUTH
   ========================================================= */

function authGoogleLogin(){

  const config =
    window.TRACEMAIL_CONFIG || {};

  const oauthStart =
    config.OAUTH_START ||
    '/auth/google/login';

  window.location.href =
    oauthStart;
}


/* =========================================================
   6. CHECK CURRENT BACKEND SESSION
   ========================================================= */

async function checkBackendAuthentication(){

  try{

    const response = await fetch(
      '/auth/me',
      {
        method: 'GET',
        credentials: 'include'
      }
    );


    if(!response.ok){

      return false;

    }


    const data =
      await response.json();


    if(
      data.authenticated &&
      data.user
    ){

      displayAuthenticatedUser(
        data.user
      );

      unlockTraceMail(
        'session',
        data.user
      );

      return true;

    }


    return false;

  }catch(error){

    console.error(
      'Backend authentication check failed:',
      error
    );

    return false;

  }

}


/* =========================================================
   7. LOGOUT
   ========================================================= */

async function logoutTraceMail(){

  try{

    const response = await fetch(
      '/auth/logout',
      {
        method: 'POST',
        credentials: 'include'
      }
    );


    if(!response.ok){

      console.warn(
        'Backend logout returned:',
        response.status
      );

    }

  }catch(error){

    console.error(
      'Logout request failed:',
      error
    );

  }


  /* ---------- Clear frontend session hints ---------- */

  sessionStorage.removeItem(
    'tmAuthenticated'
  );

  localStorage.removeItem(
    'tmUserName'
  );

  localStorage.removeItem(
    'tmUserEmail'
  );

  localStorage.removeItem(
    'tmRole'
  );


  /* ---------- Show login gate ---------- */

  const gate =
    document.getElementById('authGate');

  if(gate){

    gate.classList.remove('hidden');

    gate.setAttribute(
      'aria-hidden',
      'false'
    );

  }

  document.body.classList.add(
    'authLocked'
  );


  showLoginMode();

  toast(
    'Logged out successfully'
  );

}


/* =========================================================
   8. LOGIN / REGISTER MODE SWITCH
   ========================================================= */

function showRegisterMode(){

  const loginMode =
    document.getElementById('loginMode');

  const registerMode =
    document.getElementById('registerMode');


  if(loginMode){

    loginMode.hidden = true;

  }


  if(registerMode){

    registerMode.hidden = false;

  }

}


function showLoginMode(){

  const loginMode =
    document.getElementById('loginMode');

  const registerMode =
    document.getElementById('registerMode');


  if(registerMode){

    registerMode.hidden = true;

  }


  if(loginMode){

    loginMode.hidden = false;

  }

}


/* =========================================================
   9. EML LOCAL INTAKE
   ========================================================= */

function setupAuthEmlHandler(){

  const af =
    document.getElementById('authEml');

  if(!af){

    return;

  }


  af.addEventListener(
    'change',
    async event => {

      const file =
        event.target.files?.[0];

      if(!file){

        return;

      }


      if(!/\.eml$/i.test(file.name)){

        toast(
          'Please select a valid .eml file'
        );

        return;

      }


      try{

        const raw =
          await file.text();


        const rawEl =
          document.getElementById('raw');


        if(rawEl){

          rawEl.value = raw;

        }


        localStorage.setItem(
          'tmPendingEml',
          raw
        );


        /*
          EML is evidence intake.

          Authentication is still handled
          separately by the backend session.
        */

        toast(
          'EML evidence loaded locally'
        );


      }catch(error){

        console.error(
          'Unable to read EML:',
          error
        );

        toast(
          'Unable to read the EML file'
        );

      }

    }
  );

}


/* =========================================================
   10. AUTH UI INITIALIZATION
   ========================================================= */

document.addEventListener(
  'DOMContentLoaded',
  async () => {

    const showRegisterBtn =
      document.getElementById(
        'showRegisterBtn'
      );

    const showLoginBtn =
      document.getElementById(
        'showLoginBtn'
      );


    showRegisterBtn?.addEventListener(
      'click',
      showRegisterMode
    );


    showLoginBtn?.addEventListener(
      'click',
      showLoginMode
    );


    setupAuthEmlHandler();


    /*
      IMPORTANT:

      Do NOT trust sessionStorage as proof
      of authentication.

      Always ask the backend.
    */

    const authenticated =
      await checkBackendAuthentication();


    const gate =
      document.getElementById('authGate');


    if(!authenticated){

      if(gate){

        gate.classList.remove('hidden');

        gate.setAttribute(
          'aria-hidden',
          'false'
        );

      }

      document.body.classList.add(
        'authLocked'
      );

    }

  }
);