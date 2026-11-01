VAJRA DASHBOARD
1) npm install
2) Demo (no hardware):   node server.js            -> http://localhost:3000  (use "Simulate attack" button, press it twice for cutoff)
3) Live:  Windows: set SENDER_PORT=COM3 & set RECEIVER_PORT=COM4 & set INTRUDER_PORT=COM5 & node server.js
          Linux/Mac: SENDER_PORT=/dev/ttyUSB0 RECEIVER_PORT=/dev/ttyUSB1 INTRUDER_PORT=/dev/ttyUSB2 node server.js
   Close the Arduino Serial Monitor first (only one program can hold a COM port).
4) For the cutoff switch to control hardware, apply receiver_patch.txt to the receiver sketch and re-flash.
5) Edit the contact numbers in public/index.html (the lab officer number is a placeholder).
