# tonnerre - Crypto 200
Description:
```
We were pretty sure the service at tonnerre.pwning.xxx:8561 (source) was totally secure. But then we came across this website and now we’re having second thoughts... We think they store the service users in the same database?
```

This challenge had two parts, a website and a [server](public_server_ea2e768e20e89fb1aafbbc547cdb4636.py) that shared the same database.

The website was vunerable to SQL injection.  To get the user, salt, and verifier needed for the python server, you could inject a union into the password field to have the server reply with their values:
```
' union select user from users limit 1 offset 0#
' union select salt from users limit 1 offset 0#
' union select verifier from users limit 1 offset 0#
```

This resulted in finding a user with username:
```
get_flag
```
a salt of:
```
d14058efb3f49bd1f1c68de447393855e004103d432fa61849f0e5262d0d9e8663c0dfcb877d40ea6de6b78efd064bdd02f6555a90d92a8a5c76b28b9a785fd861348af8a7014f4497a5de5d0d703a24ff9ec9b5c1ff8051e3825a0fc8a433296d31cf0bd5d21b09c8cd7e658f2272744b4d2fb63d4bccff8f921932a2e81813
```
and a verifier of:
```
ebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59
```

These are variables that are stored to use the Secure Remote Password (SRP) protocol.
The verifier is essentially substituted for the password in the database and the actual password is never sent directly over the network.
Papers on SRP old me that because of this, if an attacker obtained the verifier, they would not gain the user's password.

The protocol is very similar to a Diffie Hellman exchange.  It uses a global N and g.  SRP also implements a hash function, H.

Here's the basic version that the challenge server implemented:

Client calculates:
```
I = username

a = rand()
A = pow(g, a, N)
```
The client sends I and A to the server.

Server calculates:
```
v = verifier
s = salt

b = rand()
B = (pow(g, b, N) + v) % N
```
The server sends s and B to the client.

The client calculates the session key (K):
```
x = H(s + I + password)
K = H(pow(B - pow(g, x, N), a + x, N))
```

The server calculates the session key (K):
```
K = H(pow(A*v, b, N))
```

The client then sends some sort of proof/verification to the server to confirm that they have agreed on the same session key.

===

Essentially, the following needs to be true to calulcate a session key:
```
H(pow((B - pow(g, x, N)), a + x, N)) == H(pow(A*v, b, N)) 
```

Since the hashes are equal, we can assume the values are 'equal'.  We can also do some other modifications:
```
Note:
  v = verifier = pow(g, x, N)
  B = pow(g, b, N) + pow(g, x, N)
  A = pow(g, a, N)

                          pow((B - pow(g, x, N)), a + x, N) = pow(A*v, b, N)
                          pow((B - pow(g, x, N)), a + x, N) = pow(A * pow(g, x, N), b, N)
pow((pow(g, b, N) + pow(g, x, N) - pow(g, x, N)), a + x, N) = pow(pow(g, a, N) * pow(g, x, N), b, N)
                              pow((pow(g, b, N)), a + x, N) = pow(pow(g, a, N) * pow(g, x, N), b, N)
      pow((pow(g, b, N)), a, N) * pow((pow(g, b, N)), x, N) = pow(pow(g, a, N) * pow(g, x, N), b, N)
```

So basically...
```
((g^b)^a) * ((g^b)^x) = ((g^a) * (g^x))^b    MOD N
```

From this, you can see that if both sides are multiplied by the modular inverse of ```g^x```, then it will be:
```
(g^b)^a = (g^a)^b
```
We can calculate this since we have ```g^b``` by subtracting the verifier from B!

For this to work, I just modified the ```A``` value I sent to also be multiplied by the inverse if the verifier (```g^x```):
```
a = rand()
A = g^a MOD N
newA = A * (v^-1)
```

After you send this to the server, you can calculated the session key by:
```
K = H((B-v)^a)
```

Send this to the server and get the flag!
```
Congratulations! The flag is PCTF{SrP_v1_BeSt_sRp_c0nf1rm3d}
```

Source can be found in [srp.py](srp.py)
