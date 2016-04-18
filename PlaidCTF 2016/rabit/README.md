# rabit - Crypto 175
Description:
```
Just give me a bit, the least significant's enough. Just a second we’re not broken, just very, very insecure. Running at rabit.pwning.xxx:7763
```

Source for the challenge can be found [here](rabit_8b98cc38ab1d0597ee51a30425d34d2e.tgz).

After you connect to the challenge and solve the hash, you are given N and the encrypted flag.  You then can have the server decrypt any submitted value and reply with the least significant bit (lsb).

My initial method to solve this challenge was to have the server decrypt the flag, receive the lsb, shift the flag right by one, and repeat.
I would shift the flag right by one by multiplying the encrypted flag with the inverse of 2 to a certain power.  

This method did not seem to work immediately. After some googling (actually the first link..), I found [http://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack](http://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack).

Basically, it means that you can use a binary-search-like method.
I could just multiply the encrypted flag with 2 and send that result to the server.
If the replied lsb was 0, the decrypted value was even, otherwise it was odd.

I kept track of an upper and lower bounds, which were initialized to N and 0 respectively.
If the decrypted value was even, the upper bounds became the middle value between upper and lower.
If the value was odd, then the lower bounds became the middle value.

After running this for awhile, the values of the upper and lower bounds where a few values apart.  Since encrypted texts are padded until they are 1023 bytes in size, I this is okay, since the encrypted text is a lot smaller than the length of N.

I just had my script innefficiently run 1024 times and print the flag:
```
PCTF{LSB_is_4ll_y0u_ne3d}
```

The source can be found in [lsb.py](lsb.py)
