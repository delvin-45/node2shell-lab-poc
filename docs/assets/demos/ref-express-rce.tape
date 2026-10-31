# VHS v0.12.1. Start the reference lab with N2S_SUPERVISE=1 before rendering.
Output docs/assets/demos/ref-express-rce.gif
Output docs/assets/demos/ref-express-rce.mp4
Output docs/assets/demos/ref-express-rce.ascii

Set Shell "powershell"
Set Width 1200
Set Height 700
Set FontSize 18
Set TypingSpeed 20 ms
Set Framerate 10
Set PlaybackSpeed 2

Type "python -u poc.py --profile n2s-ref-express-24.22.0-x86_64 --mode rce --timeout 30"
Enter
Wait+Screen@1200s /PASS: RCE verified/
Wait+Screen@15s /fresh id output/
Sleep 3s
