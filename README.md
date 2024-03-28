## NODE-AUTH-CSRF

<p>node-auth-csrf is a lightweight library designed for csrf protection.</p>

### INSTALLATION
You can install node-auth-csrf via npm:
```
npm install node-auth-csrf
```
### USAGE

<p>To integrate node-auth-csrf into your express application, follow these simple steps:</p>
<br/>

<b># Functions</b>

```
const { csrfProtection } = require('node-auth-csrf');
```
<p><b>csrfProtection</b> - used to initialize node-auth-csrf</p>
<p><b>generateToken</b> - used for generating token</p>

### EXAMPLE
```
const express = require('express');
const { csrfProtection } = require('node-auth-csrf');

const app = express();

app.use(csrfProtection(process.env.CSRF_SECRET));
app.get("/csrf-token", (req, res) => {
    const csrfToken = req.csrfProtection.generateToken();
    res.json({ csrfToken });
});

app.get('/protected', (req, res) => {
    res.send(req.user);
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

<p>Here all POST, PUT and DELETE route will be protected by node-auth-csrf</p>
`x-csrf-token` must exist on the header of the request to be able to authorize the request.

```
headers: {
  'x-csrf-token': 'generated token'
}
```

### GUIDES
<p>You can also use csrfProtection on specific route your group of route if you don't want to put it globally</p>

```
app.get('/protected', csrfProtection(process.env.CSRF_SECRET), (req, res) => {
    res.send(req.user);
});
```

OR

```
app.use('/protected', csrfProtection(process.env.CSRF_SECRET), protectedRoutes);
```
