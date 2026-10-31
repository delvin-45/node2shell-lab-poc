# VHS v0.12.1. Start compose.scan.yaml before rendering.
Output docs/demo/scan.gif
Output docs/demo/scan.mp4
Output docs/demo/scan.ascii

Set Shell "powershell"
Set Width 1200
Set Height 700
Set FontSize 18
Set TypingSpeed 15 ms
Set Framerate 10
Set PlaybackSpeed 2

Type "python scan.py --assets assets.txt"
Enter
Wait+Screen@60s /summary/
Sleep 4s
